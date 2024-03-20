DROP TABLE IF EXISTS `pre__action_log`;
CREATE TABLE `pre__action_log` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '日志id',
  `name` varchar(250) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '操作账号信息',
  `url` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `method` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '请求类型',
  `info` text COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '内容信息',
  `useragent` text COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'user-agent',
  `time` int(10) DEFAULT NULL COMMENT '记录时间',
  `ip` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `status` char(3) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '输出状态',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=COMPACT COMMENT='操作日志';

DROP TABLE IF EXISTS `pre__admin`;
CREATE TABLE `pre__admin` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `password` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_salt` char(6) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nickname` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `avatar` char(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `introduce` mediumtext COLLATE utf8mb4_unicode_ci,
  `is_root` tinyint(1) DEFAULT NULL,
  `status` tinyint(1) NOT NULL,
  `refresh_time` int(10) NOT NULL DEFAULT '0' COMMENT '刷新时间',
  `refresh_ip` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '刷新ip',
  `last_active` int(10) DEFAULT NULL,
  `last_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `update_time` int(10) DEFAULT NULL,
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `add_time` int(10) DEFAULT NULL,
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `pre__attachment`;
CREATE TABLE `pre__attachment` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `owner_id` char(36) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '关联类型id',
  `owner_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '附件关联类型',
  `name` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '文件名',
  `path` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件路径',
  `mime` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件mime类型',
  `extension` varchar(15) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件类型',
  `size` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0' COMMENT '文件大小',
  `md5` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件md5',
  `sha1` char(40) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'sha1 散列值',
  `disk` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'public' COMMENT '上传驱动',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) NOT NULL DEFAULT '0' COMMENT '更新时间',
  `create_time` int(10) NOT NULL DEFAULT '0' COMMENT '上传时间',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加ip',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='附件表';

DROP TABLE IF EXISTS `pre__auth_group`;
CREATE TABLE `pre__auth_group` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `parentid` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `title` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `listorder` int(10) DEFAULT NULL,
  `status` tinyint(1) NOT NULL,
  `update_time` int(10) DEFAULT NULL,
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `add_time` int(10) DEFAULT NULL,
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `pre__auth_group_access`;
CREATE TABLE `pre__auth_group_access` (
  `admin_id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `group_id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`admin_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `pre__auth_rule`;
CREATE TABLE `pre__auth_rule` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则id',
  `parentid` char(36) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '上级id',
  `title` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则中文描述',
  `url` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '访问地址',
  `method` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'get' COMMENT '请求类型',
  `slug` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '地址鉴权标识',
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '描述',
  `listorder` int(10) NOT NULL DEFAULT '100' COMMENT '排序id',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '更新ip',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加ip',
  PRIMARY KEY (`id`),
  KEY `module` (`status`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='规则表';

DROP TABLE IF EXISTS `pre__auth_rule_access`;
CREATE TABLE `pre__auth_rule_access` (
  `group_id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `rule_id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  PRIMARY KEY (`rule_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='用户组与权限关联表';

DROP TABLE IF EXISTS `pre__rules`;
CREATE TABLE `pre__rules` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `ptype` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v0` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v1` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v2` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v3` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v4` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `v5` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ptype` (`ptype`(191)),
  KEY `v0` (`v0`(191)),
  KEY `v1` (`v1`(191)),
  KEY `v2` (`v2`(191)),
  KEY `v3` (`v3`(191)),
  KEY `v4` (`v4`(191)),
  KEY `v5` (`v5`(191))
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=COMPACT COMMENT='casbin权限表';

DROP TABLE IF EXISTS `pre__extension`;
CREATE TABLE `pre__extension` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(160) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '扩展包名',
  `title` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '扩展名称',
  `version` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '扩展版本',
  `adaptation` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '适配系统版本',
  `info` text COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '扩展信息',
  `listorder` int(10) DEFAULT '100' COMMENT '排序ID',
  `status` tinyint(1) DEFAULT '1' COMMENT '状态',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '更新IP',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加ip',
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=COMPACT COMMENT='已安装模块列表';


INSERT INTO `pre__admin` VALUES ('01cabd82-060d-405f-ba47-4d79fc47efcf','lakego','8966aff5289184448a004af81373c8f9','gazqzd','lakego','lakego@admin.com','5acfcd19-3a4c-4a28-8386-ae877952fd11','lakego-admin 是基于 gin、jwt 和 rbac 的 go 后台管理系统',0,1,0,'',1652759635,'127.0.0.1',1652587697,'127.0.0.1',1652545221,'127.0.0.1'),('642eb7b3-91ea-4808-bba6-f5f10938929a','admin','2a9b6b430ebe2f4257639e62ff9321bb','chNI7n','管理员','lakego-admin@admin.com','1f3cd4fb-f7e4-4b41-8663-167ca23ea5ab','lakego-admin 是基于 gin、jwt 和 rbac 的 go 后台管理系统',1,1,0,'',1675937003,'127.0.0.1',1652587697,'127.0.0.1',1652545221,'127.0.0.1');
INSERT INTO `pre__auth_group` VALUES ('277cbc81-be2c-4fab-9240-5feccb2c024c','0','管理员组','账号管理员组',105,1,1656389180,'127.0.0.1',1621431751,'127.0.0.1'),('bcf40e54-4802-45b4-b3e6-7021ec755083','0','超级管理员组','拥有全部管理权限',95,1,1652586071,'127.0.0.1',1621431751,'127.0.0.1');
INSERT INTO `pre__auth_group_access` VALUES ('01cabd82-060d-405f-ba47-4d79fc47efcf','277cbc81-be2c-4fab-9240-5feccb2c024c'),('642eb7b3-91ea-4808-bba6-f5f10938929a','277cbc81-be2c-4fab-9240-5feccb2c024c');
