#ifndef OPTIMACK_RECV_BUFFER_H
#define OPTIMACK_RECV_BUFFER_H

#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>

class RecvBuffer {
public:
    struct Segment {
        int len;
        unsigned char* data;
        Segment() : len(0), data(NULL) {}
        Segment(unsigned char* data_, int len_) : len(len_), data(data_) {}
    };

    using SendFn = std::function<void(unsigned int, unsigned char*, int)>;
    using AckUpdateFn = std::function<void(unsigned int)>;

    RecvBuffer();
    ~RecvBuffer();

    bool insert(unsigned int seq, const unsigned char* data, int len, bool append_terminator);
    int sendOutOfOrder(unsigned int seq, const SendFn& send_data);
    int sendOutOfOrder(unsigned int start, unsigned int end, const SendFn& send_data);
    int sendOutOfOrder(unsigned int start, unsigned int end, int max_count, const SendFn& send_data);
    int sendLastInorder(unsigned int end, const SendFn& send_data);
    int removeReceived(unsigned int seq);

    int senderLoop(bool debug, const SendFn& send_data, const AckUpdateFn& update_ack);

    void notifyOne();
    void requestStop();
    void resetSender(unsigned int start_seq);
    void clear();

private:
    void freeSegment(Segment& segment);

    std::map<unsigned int, Segment> segments_;
    std::mutex mutex_;
    std::condition_variable cv_;
    unsigned int last_sent_seq_;
    bool sender_stop_;
};

#endif // OPTIMACK_RECV_BUFFER_H
