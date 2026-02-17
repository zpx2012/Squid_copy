#include "recv_buffer.h"

#include <iterator>
#include <stdlib.h>
#include <string.h>

#include "logging.h"

RecvBuffer::RecvBuffer() : last_sent_seq_(1), sender_stop_(false) {}

RecvBuffer::~RecvBuffer()
{
    requestStop();
    clear();
}

void RecvBuffer::freeSegment(Segment& segment)
{
    if (segment.data) {
        free(segment.data);
        segment.data = NULL;
    }
    segment.len = 0;
}

bool RecvBuffer::insert(unsigned int seq, const unsigned char* data, int len, bool append_terminator)
{
    const int alloc_len = append_terminator ? len + 1 : len;
    unsigned char* payload = (unsigned char*)malloc(alloc_len);
    if (!payload) {
        log_error("insert_to_recv_buffer: can't malloc for %d bytes", alloc_len);
        return false;
    }

    memset(payload, 0, alloc_len);
    memcpy(payload, data, len);

    std::lock_guard<std::mutex> lk(mutex_);
    auto ret = segments_.insert(std::pair<unsigned int, Segment>(seq, Segment(payload, len)));
    if (ret.second) {
        return true;
    }

    if (ret.first->second.len < len) {
        freeSegment(ret.first->second);
        segments_.erase(ret.first);
        segments_.insert(std::pair<unsigned int, Segment>(seq, Segment(payload, len)));
        return true;
    }

    free(payload);
    return false;
}

int RecvBuffer::sendOutOfOrder(unsigned int start, unsigned int end, int max_count, const SendFn& send_data)
{
    std::lock_guard<std::mutex> lk(mutex_);
    int count = 0;
    for (auto it = segments_.begin(); it != segments_.end(); ++it) {
        if (it->first <= start && start < it->first + it->second.len - 1) {
            for (auto cur = it; cur != segments_.end() && count < max_count; ++cur, ++count) {
                if (cur->first < end) {
                    send_data(cur->first, cur->second.data, cur->second.len);
                } else {
                    break;
                }
            }
            break;
        } else if (it->first > start) {
            break;
        }
    }
    return 0;
}

int RecvBuffer::sendOutOfOrder(unsigned int start, unsigned int end, const SendFn& send_data)
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto it = segments_.begin(); it != segments_.end(); ++it) {
        if (it->first <= start && start < it->first + it->second.len - 1) {
            for (auto cur = it; cur != segments_.end(); ++cur) {
                if (cur->first + cur->second.len <= end) {
                    send_data(cur->first, cur->second.data, cur->second.len);
                } else {
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

int RecvBuffer::sendOutOfOrder(unsigned int seq, const SendFn& send_data)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (segments_.size() < 2) {
        return 0;
    }

    bool found = false;
    for (auto prev = segments_.begin(), cur = std::next(prev);
         prev != segments_.end() && cur != segments_.end();
         prev = cur, ++cur) {
        if (prev->first + prev->second.len >= cur->first) {
            found = true;
            send_data(prev->first, prev->second.data, prev->second.len);
            freeSegment(prev->second);
            segments_.erase(prev);
            continue;
        } else if (found) {
            send_data(prev->first, prev->second.data, prev->second.len);
            freeSegment(prev->second);
            segments_.erase(prev);
            break;
        }

        if (cur->first > seq) {
            break;
        }
    }
    return 0;
}

int RecvBuffer::sendLastInorder(unsigned int end, const SendFn& send_data)
{
    std::lock_guard<std::mutex> lk(mutex_);
    bool found = false;
    for (auto prev = segments_.begin(); prev != segments_.end();) {
        auto cur = std::next(prev);
        const unsigned int prev_upper = prev->first + prev->second.len;
        if (cur == segments_.end()) {
            if (prev_upper <= end) {
                send_data(prev->first, prev->second.data, prev->second.len);
                freeSegment(prev->second);
                segments_.erase(prev);
            }
            break;
        }
        if (prev_upper <= end) {
            if (prev_upper >= cur->first) {
                send_data(prev->first, prev->second.data, prev->second.len);
                found = true;
            } else {
                if (found) {
                    send_data(cur->first, cur->second.data, cur->second.len);
                    freeSegment(cur->second);
                    segments_.erase(cur);
                }
                break;
            }
        } else {
            break;
        }
        freeSegment(prev->second);
        segments_.erase(prev);
        prev = cur;
    }
    return 0;
}

int RecvBuffer::removeReceived(unsigned int seq)
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto it = segments_.begin(); it != segments_.end();) {
        if (it->first + it->second.len - 1 < seq) {
            freeSegment(it->second);
            segments_.erase(it++);
            continue;
        }
        break;
    }
    return 0;
}

int RecvBuffer::senderLoop(bool debug, const SendFn& send_data, const AckUpdateFn& update_ack)
{
    const int MAX_BUF_LEN = 1460 * 10 + 1;
    unsigned char buf[MAX_BUF_LEN] = {0};
    int buf_len = 0;

    while (true) {
        std::unique_lock<std::mutex> lk(mutex_);
        cv_.wait(lk, [this] { return sender_stop_ || !segments_.empty(); });
        if (sender_stop_) {
            break;
        }

        memset(buf, 0, MAX_BUF_LEN);
        buf_len = 0;
        if (debug) {
            print_func("send_data_to_squid_thread: wake up\n");
        }

        for (auto prev = segments_.begin(); prev != segments_.end();) {
            if (debug) {
                print_func("send_data_to_squid_thread:[%u, %u], seq %u",
                           prev->first, prev->first + prev->second.len, last_sent_seq_);
            }
            if (prev->first <= last_sent_seq_ && prev->first + prev->second.len > last_sent_seq_) {
                memcpy(buf + buf_len, prev->second.data, prev->second.len);
                buf_len += prev->second.len;

                auto cur = std::next(prev);
                for (int count = 0; prev != segments_.end() && cur != segments_.end() && count < 100;
                     prev = cur, ++cur, ++count) {
                    if (prev->first + prev->second.len >= cur->first) {
                        if (buf_len + cur->second.len >= MAX_BUF_LEN) {
                            send_data(prev->first - buf_len + prev->second.len, buf, buf_len);
                            memset(buf, 0, MAX_BUF_LEN);
                            buf_len = 0;
                            last_sent_seq_ = prev->first + prev->second.len;
                            update_ack(last_sent_seq_);
                        }
                        memcpy(buf + buf_len, cur->second.data, cur->second.len);
                        buf_len += cur->second.len;
                        freeSegment(prev->second);
                        segments_.erase(prev);
                    } else {
                        break;
                    }
                }

                if (buf_len) {
                    send_data(prev->first - buf_len + prev->second.len, buf, buf_len);
                    memset(buf, 0, MAX_BUF_LEN);
                    buf_len = 0;
                    last_sent_seq_ = prev->first + prev->second.len;
                    update_ack(last_sent_seq_);
                }
                break;
            } else if (prev->first > last_sent_seq_) {
                break;
            }
            freeSegment(prev->second);
            segments_.erase(prev++);
        }
    }

    return 0;
}

void RecvBuffer::notifyOne()
{
    cv_.notify_one();
}

void RecvBuffer::requestStop()
{
    {
        std::lock_guard<std::mutex> lk(mutex_);
        sender_stop_ = true;
    }
    cv_.notify_all();
}

void RecvBuffer::resetSender(unsigned int start_seq)
{
    std::lock_guard<std::mutex> lk(mutex_);
    sender_stop_ = false;
    last_sent_seq_ = start_seq;
}

void RecvBuffer::clear()
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& item : segments_) {
        freeSegment(item.second);
    }
    segments_.clear();
}
