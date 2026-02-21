import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np
from datetime import datetime
import matplotlib
from matplotlib import font_manager
from matplotlib.lines import Line2D

# ---------- Configuration & Styles ----------
font_params = {'fontname': 'serif', 'fontsize': 11}
font_path = font_manager.findfont(font_manager.FontProperties(family="serif"))
font_prop = font_manager.FontProperties(fname=font_path, weight="bold", size=11)

plt.rcParams["hatch.linewidth"] = 0.5
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"]  = 42
plt.rcParams["lines.linewidth"]     = 2

def load_csv(in_file):
    df = pd.read_csv(in_file, sep=',')
    # df.columns = ['optim_num','range_group_num','range_duplica_num','speed','last_speed','duration','efficiency','recved_bytes','total_bytes','error_cnt']
    df = df[ df.last_speed > 0 ]
    df.speed = df.speed * 8 / 1000.0
    df.efficiency = df.efficiency
    df = df[ df.duration >= 59 ]
    df = df[ df.total_bytes > 1 ]
    return df

def group_df(df):
    df_mean = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).mean()
    df_mean['count'] = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).size()[['size']]
    df_mean['err_cnt'] = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).agg({'error_cnt':sum})['error_cnt']
    print(df_mean)
    df_mean.to_csv(in_file.replace('.csv',"_union.csv"), encoding='utf-8',index=False)
    return df_mean

def reform_df(df, by_tag, legend_tag, legend_lim, keywords):
    union_df = 0
    first = 0
    by_col = 'range_%s_num' % by_tag
    y_col = 'range_%s_num' % legend_tag
    for i in range(1,4):#3, 4
    # for i in [1]:
        # for j in [1, 3, 6]:
        for j in range(1,legend_lim):
            # df_sub = df[ df.optim_num == i ]
            df_sub = df[ df[y_col] == j ]
            df_sub = df_sub[ df_sub.optim_num == i ]
            df_sub = df_sub[ [by_col] + keywords ]
            keywords_tag = [ kw + '_' + str(i)+'optim+'+str(j)+legend_tag for kw in keywords]
            df_sub.columns = [by_col, str(i)+'optim+'+str(j)+legend_tag]
            if not first:
                union_df = df_sub
                first = 1
            else:
                union_df = pd.merge(union_df,df_sub,on=[by_col],how='outer')
    union_df.sort_values(by=[by_col],inplace=True)
    # union_df.to_csv(out_file, encoding='utf-8',index=False)
    print(union_df)
    return union_df


def reform_df_per_optim(df, i, by_tag, legend_tag, legend_lim, keywords):
    union_df = 0
    first = 0
    by_col = 'range_%s_num' % by_tag
    y_col = 'range_%s_num' % legend_tag
    # for i in range(1,4):#3, 4
    for j in range(1,legend_lim):
        df_sub = df[ df[y_col] == j ]
        df_sub = df_sub[ df_sub.optim_num == i ]
        df_sub = df_sub[ [by_col] + keywords ]
        keywords_tag = [ kw + '_' + str(i)+'optim+'+str(j)+legend_tag for kw in keywords]
        df_sub.columns = [by_col, str(i)+'optim+'+str(j)+legend_tag]
        if not first:
            union_df = df_sub
            first = 1
        else:
            union_df = pd.merge(union_df,df_sub,on=[by_col],how='outer')
    union_df.sort_values(by=[by_col],inplace=True)
    # union_df.to_csv(out_file, encoding='utf-8',index=False)
    print(union_df)
    return union_df


# def reform_df_duplica(df, keyword, out_file):
#     union_df = 0
#     first = 0
#     for i in range(1,4):
#         for j in range(1,7):
#             df_sub = df[ df.optim_num == i ]
#             df_sub = df_sub[ df_sub.range_duplica_num == j ]
#             df_sub = df_sub[ ['range_group_num', keyword] ]
#             df_sub.columns = ['range_group_num', str(i)+'optim+'+str(j)+'duplica']
#             if not first:
#                 union_df = df_sub
#                 first = 1
#             else:
#                 union_df = pd.merge(union_df,df_sub,on=['range_group_num'],how='outer')
#     union_df.sort_values(by=['range_group_num'],inplace=True)
#     union_df.to_csv(out_file, encoding='utf-8',index=False)
#     print(union_df)
#     return union_df


def plot(df1, df2, out_file):
    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(9, 4))
    axes1 = df1.plot(ax=axes[0], x='range_duplica_num', ylim=(0, 10), legend=False) #figsize=(6.4,4.2)
    for i, line in enumerate(axes1.get_lines()):
        line.set_marker(markers[i%(len(markers))])
    axes1.set_xlabel('Number of Duplicate Range Request Connection(s)')
    axes1.set_ylabel('Goodput (Mbps)')

    axes2 = df2.plot(ax=axes[1], x='range_duplica_num', ylim=(0, 100), legend=False)
    for i, line in enumerate(axes2.get_lines()):
        line.set_marker(markers[i%(len(markers))])    
    axes2.set_xlabel('Number of Duplicate Range Request Connection(s)')
    axes2.set_ylabel('Efficiency (%)')

    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5)) #
    fig.suptitle(title)
    # fig.legend(loc=7)
    # fig.legend(loc="center right", bbox_to_anchor=(1.8, 0.5)) #bbox_to_anchor=(0, -0.6, 1, 0.2), ncol=3,

    # plt.tight_layout() #rect=[0, 0, 0.75, 1]
    # plt.suplots_adjust(right=0.75)
    plt.savefig(out_file, bbox_inches="tight") #transparent=True

def single_plot(axe, df, xcol, xlabel, ylabel, ylim, with_title):
    axes1 = df.plot(ax=axe, x=xcol, legend=False)
    for i, line in enumerate(axes1.get_lines()):
        line.set_marker(markers[i%(len(markers))])
        line.set_markersize(5)

    axes1.set_title(with_title, y=-0.7, pad=10, **font_params)
    axes1.set_ylabel(ylabel, **font_params)
    axes1.set_xlabel(xlabel,**font_params)

    # axes1.tick_params(axis='both', which='major', labelsize=8, direction='in', pad=2)
    # for tick in axes1.xaxis.get_majorticklabels():
    #     tick.set_fontsize(9)
    #     tick.set_fontname('serif')
    # Grid and Spines
    axes1.grid(axis='y', linestyle=':', color='gray', alpha=0.5, zorder=0)
    axes1.spines['top'].set_visible(False)
    axes1.spines['right'].set_visible(False)
    axes1.spines['left'].set_linewidth(0.8)
    axes1.spines['bottom'].set_linewidth(0.8)
    if ylim:
        axes1.set_ylim(0, ylim)

    # axes1.text(0.5, -0.45, xlabel,
    #             horizontalalignment='center',
    #             verticalalignment='top',
    #             transform=axes1.transAxes,
    #             **font_params)

def boxplot(df, keyword, out_file, lim):
    ax = 0
    for i in range(1,4):
        for j in range(1,7):
            col_name = str(i)+'optim+'+str(j)+'duplica'
            df_sub = df[ df.optim_num == i ]
            df_sub = df_sub[ df_sub.range_duplica_num == j ]
            df_sub = df_sub[ ['range_group_num', keyword] ]
            df_sub.columns = ['range_group_num', col_name]
            # if not ax:
                # ax = df_sub.boxplot(column=str(i)+'optim+'+str(j)+'duplica', by='range_group_num')
            # else:
            df_sub.boxplot(column=col_name, by='range_group_num', showmeans=True)
            plt.savefig(out_file+'_'+col_name+'.png')
            # plt.boxplot(list(df_sub[[str(i)+'optim+'+str(j)+'duplica']]), positions=list(df_sub[['range_group_num']]))
    # fig = df.boxplot(column=[keyword], by=['optim_num', 'range_group_num', 'range_duplica_num'], )
    # ax.legend(bbox_to_anchor=(0, -0.4, 1, 0.2), loc="lower center", mode="expand", ncol=3, fancybox=True)
    # plt.ylim(0, lim)
    # # plt.title(title)
    # plt.tight_layout()
    # plt.savefig(out_file) #transparent=True

in_file = os.path.expanduser(sys.argv[1])
# title = sys.argv[2]
markers = ['H', '^', 'v', 's', '3', '.', '1', '_', 'x', ',', '*', '+']
ylims = {'speed':11, 'efficiency':100, 'count':10, 'request_delay_avg':1, 'resp_delay_avg':3, 'detect_delay_avg':15, 'timeout_delay_sum':300}
labels = {'speed': 'Goodput (Mbps)', 'efficiency': 'Efficiency (%)', 'count':'Count', 'request_delay_avg':'Request Delay(s)', 'resp_delay_avg':'Response Delay(s)', 'detect_delay_avg':"Detect Delay(s)", 'timeout_delay_sum':'Timeout Delay'}


df = load_csv(in_file)
df_mean = group_df(df)

keywords = ['speed', 'efficiency'] #, 
# keywords = ['speed','request_delay_avg','resp_delay_avg'] #'request_delay_max', ,'resp_delay_max'  'efficiency'
# keywords = ['speed','detect_delay_avg','request_delay_avg',] #'request_delay_max', ,'resp_delay_max'  'efficiency'
#keywords = ['speed','timeout_delay_sum','resp_delay_avg']
ncol = len(keywords)
nrow = 3
fig, axes = plt.subplots(figsize=(7.2, 3.6), nrows=ncol, ncols=nrow, sharex=True) #, constrained_layout=True
plt.subplots_adjust(top=0.75, bottom=0.2, wspace=0.3)

for i in range(ncol):
    keyword = keywords[i]
    if nrow == 1:
        # df_reform = reform_df(df_mean, 'duplica', 'group', 7, [keyword]) #[ df_mean.optim_num == j]
        df_reform = reform_df(df_mean, 'group', 'duplica', 7, [keyword]) #[ df_mean.optim_num == j]
        if ncol == 1:
            single_plot(axes, df_reform, 'range_group_num', '', labels[keyword], ylims[keyword], True)
        else:
            single_plot(axes[i], df_reform, 'range_duplica_num', '', labels[keyword], ylims[keyword], True)
    else:
        captions = ['(a)1 Optimistic Connection', '(b)2 Optimistic Connections', '(c)3 Optimistic Connections']
        all_captions = [['','',''], captions]
        for j in range(nrow):
            df_reform = reform_df_per_optim(df_mean, j+1, 'group', 'duplica', 5, [keyword]) #[ df_mean.optim_num == j]
            # print(type(df_reform))
            xlabel, ylabel, title = '','',''
            if j == 0:
                ylabel = labels[keyword]
            if i == 1:
                title = captions[j]
                xlabel = 'Number of Backup Groups'

            single_plot(axes[i][j], df_reform, 'range_group_num', xlabel, ylabel, ylims[keyword], title)
        # df_reform = reform_df(df_mean, 'duplica', 'group', 7, [keyword])
        # single_plot(axes[i], df_reform, 'range_duplica_num', 'Number of Duplicate Range Request Connection(s)', labels[keyword], ylims[keyword])


handles, labels = axes[0][0].get_legend_handles_labels()
handles = [plt.plot([], marker="", ls="")[0]] + handles
fig.legend(handles,
           ['Number of Recovery Threads:', '1', '2', '3', '4'], 
           loc='upper center', 
           bbox_to_anchor=(0.5, 1.01), 
           ncol=7, 
        #    title=,
        #    title_fontsize=8,
           prop=font_prop,
           fontsize=10,
        #    handletextpad=0.4, columnspacing=1.0,
           markerfirst=False,
           frameon=False)

plt.tight_layout(rect=[0, 0, 1, 0.95])

# fig.add_subplot(111, frameon=False)
# # hide tick and tick label of the big axes
# plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
# plt.grid(False)
# plt.xlabel('Number of Backup Groups', **font_params)



#handles, labels = axes[0][0].get_legend_handles_labels()
#fig.legend(handles, ['1 TCP', '2 TCPs', '3 TCPs', '4 TCPs', '5 TCPs', '6 TCPs'], ncol=6, loc='upper center', bbox_to_anchor=(0.5, 0.95))
# fig.suptitle(title)
fig_file = in_file.replace('.csv',"_group_%s.png" % datetime.now().strftime("%Y%m%dT%H%M%S"))
plt.savefig(fig_file, bbox_inches="tight") #transparent=True

# plot(df_speed, df_effi, fig_file)
    # boxplot(df, keyword, in_file.strip('.csv'), ylims[keyword])

#Confidence Interval figure
#p value
