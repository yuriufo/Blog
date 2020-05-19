# -*- coding: utf-8 -*-
"""博客构建配置文件
"""

# For Maverick
site_prefix = "/"
source_dir = "../src/"
build_dir = "../dist/"
index_page_size = 10
archives_page_size = 20
enable_jsdelivr = {
    "enabled": True,
    "repo": "yuriufo/yuriufo.github.io@master"
}
template = {
    "name": "Kepler",
    "type": "local",
    "path": "../Kepler"
}
locale = "Asia/Shanghai"


# 站点设置
site_name = "yurisec"
site_logo = "${static_prefix}logo.png"
site_build_date = "2020-05-14T00:00+08:00"
author = "Yuri"
email = "yuripwn@gmail.com"
author_homepage = "https://www.yurisec.cn"
description = "A simple static blog."
key_words = ['Yuri', 'blog']
language = 'zh-CN'
external_links = [
    {
        "name": "ycdxsb",
        "url": "https://blog.ycdxsb.cn/",
        "brief": "🐷"
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

footer_addon = ''

body_addon = ''
