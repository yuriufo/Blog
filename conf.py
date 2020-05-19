# -*- coding: utf-8 -*-
"""博客构建配置文件
"""

# For Maverick
site_prefix = "/yuriufo-blog.github.io/"
source_dir = "../src/"
build_dir = "../dist/"
index_page_size = 10
archives_page_size = 20
template = {
    "name": "Galileo",
    "type": "local",
    "path": "../Galileo"
}
enable_jsdelivr = {
    "enabled": True,
    "repo": "yuriufo/yuriufo-blog.github.io@gh-pages"
}
locale = "Asia/Shanghai"


# 站点设置
site_name = "YuriSec"
site_logo = "${static_prefix}logo.png"
site_build_date = "2018-03-28T00:00+08:00"
author = "Yuri"
email = "yuripwn@gmail.com"
author_homepage = "https://yurisec.cn"
description = "A simple static blog."
key_words = ['Yuri', 'blog']
language = 'zh-CN'
external_links = [
    {
        "name": "ycdxsb",
        "url": "https://blog.ycdxsb.cn/",
        "brief": "🐷"
    },
    {
        "name": "mote",
        "url": "http://m0te.top/",
        "brief": "💪"
    }
]
nav = [
    {
        "name": "首页",
        "url": "${site_prefix}",
        "target": "_self"
    },
    {
        "name": "归档",
        "url": "${site_prefix}archives/",
        "target": "_self"
    },
    {
        "name": "关于",
        "url": "${site_prefix}about/",
        "target": "_self"
    }
]

social_links = [
    {
        "name": "GitHub",
        "url": "https://github.com/yuriufo",
        "icon": "gi gi-github"
    },
    {
        "name": "Weibo",
        "url": "https://weibo.com/qq771739864",
        "icon": "gi gi-weibo"
    }
]

head_addon = r'''
<meta http-equiv="x-dns-prefetch-control" content="on">
<link rel="dns-prefetch" href="//cdn.jsdelivr.net" />
'''

footer_addon = r'''
<a href="http://www.beian.miit.gov.cn/" rel="noopener" target="_blank">京ICP备20016612号</a>
'''

body_addon = ''
