# Host: localhost  (Version: 5.5.53)
# Date: 2021-07-02 23:48:52
# Generator: MySQL-Front 5.3  (Build 4.234)

/*!40101 SET NAMES utf8 */;

#
# Structure for table "lakego_lakego_admin"
#

DROP TABLE IF EXISTS `lakego_lakego_admin`;
CREATE TABLE `lakego_lakego_admin` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '用户ID',
  `name` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '管理账号',
  `password` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '管理密码',
  `password_salt` varchar(6) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '加密因子',
  `nickname` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '昵称',
  `email` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `avatar` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '头像',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `last_login_time` int(10) DEFAULT '0' COMMENT '最后登录时间',
  `last_login_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '最后登录IP',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '更新IP',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加IP',
  PRIMARY KEY (`id`),
  KEY `username` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='管理员表';

#
# Data for table "lakego_lakego_admin"
#

/*!40000 ALTER TABLE `lakego_lakego_admin` DISABLE KEYS */;
INSERT INTO `lakego_lakego_admin` VALUES ('dbe97f21a69f67fb361b0be64988ee59','lake','6b4ee75684079f24bb6331d6b4abbb57','bOMvXH','Lake','lake@qq.com','d0633455bf755b408cbc4a6b4fe2400c',1,1621520922,'127.0.0.1',1621431650,'127.0.0.1',1564415458,'2130706433'),('e92ba0a3f86f4a5693d8487eb8c632b5','admin','82b73cc50afcfdd146cc20d631864390','PaBQfr','管理员','lake-admin@qq.com','eb73eb5d52f9c663b5809b6839f2f9a6',1,1621610257,'127.0.0.1',0,'0',1564667925,'2130706433');
/*!40000 ALTER TABLE `lakego_lakego_admin` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_attachment"
#

DROP TABLE IF EXISTS `lakego_lakego_attachment`;
CREATE TABLE `lakego_lakego_attachment` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '附件关联类型',
  `type_id` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '关联类型ID',
  `name` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件名',
  `path` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件路径',
  `mime` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件mime类型',
  `ext` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件类型',
  `size` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0' COMMENT '文件大小',
  `md5` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件md5',
  `sha1` char(40) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'sha1 散列值',
  `driver` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'public' COMMENT '上传驱动',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) NOT NULL DEFAULT '0' COMMENT '更新时间',
  `create_time` int(10) NOT NULL DEFAULT '0' COMMENT '上传时间',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加IP',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='附件表';

#
# Data for table "lakego_lakego_attachment"
#

/*!40000 ALTER TABLE `lakego_lakego_attachment` DISABLE KEYS */;
INSERT INTO `lakego_lakego_attachment` VALUES ('eb73eb5d52f9c663b5809b6839f2f9a6','admin','e92ba0a3f86f4a5693d8487eb8c632b5','Penguins.jpg','images/20210519\\078d9f012c5a264dd9ee6e959c63e8ef.jpg','image/jpeg','jpg','777835','9d377b10ce778c4938b3c7e2c63a229a','df7be9dc4f467187783aca68c7ce98e4df2172d0','public',1,1621431615,1621431615,1621431615,'127.0.0.1');
/*!40000 ALTER TABLE `lakego_lakego_attachment` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_auth_group"
#

DROP TABLE IF EXISTS `lakego_lakego_auth_group`;
CREATE TABLE `lakego_lakego_auth_group` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '用户组id',
  `parentid` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0' COMMENT '父组别',
  `title` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '用户组中文名称',
  `description` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '描述信息',
  `listorder` int(10) NOT NULL DEFAULT '100' COMMENT '排序ID',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '更新IP',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加IP',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='权限组表';

#
# Data for table "lakego_lakego_auth_group"
#

/*!40000 ALTER TABLE `lakego_lakego_auth_group` DISABLE KEYS */;
INSERT INTO `lakego_lakego_auth_group` VALUES ('26d9697f66e341d56af023423d8718b3','538a712299e0ba6011aaf63f2a1317f4','编辑','网站编辑，包括对文章的添加编辑等',105,1,1621431751,'127.0.0.1',0,''),('538a712299e0ba6011aaf63f2a1317f4','0','超级管理员','拥有所有权限',95,1,0,'0',0,'');
/*!40000 ALTER TABLE `lakego_lakego_auth_group` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_auth_group_access"
#

DROP TABLE IF EXISTS `lakego_lakego_auth_group_access`;
CREATE TABLE `lakego_lakego_auth_group_access` (
  `admin_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `group_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  UNIQUE KEY `admin_id` (`admin_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=FIXED COMMENT='管理员与用户组关联表';

#
# Data for table "lakego_lakego_auth_group_access"
#

/*!40000 ALTER TABLE `lakego_lakego_auth_group_access` DISABLE KEYS */;
INSERT INTO `lakego_lakego_auth_group_access` VALUES ('dbe97f21a69f67fb361b0be64988ee59','26d9697f66e341d56af023423d8718b3');
/*!40000 ALTER TABLE `lakego_lakego_auth_group_access` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_auth_rule"
#

DROP TABLE IF EXISTS `lakego_lakego_auth_rule`;
CREATE TABLE `lakego_lakego_auth_rule` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则id',
  `parentid` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '上级ID',
  `title` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则中文描述',
  `url` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '访问地址',
  `method` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'GET' COMMENT '请求类型',
  `remark` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '提示',
  `listorder` int(10) NOT NULL DEFAULT '100' COMMENT '排序ID',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '更新IP',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加IP',
  PRIMARY KEY (`id`),
  KEY `module` (`status`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='规则表';

#
# Data for table "lakego_lakego_auth_rule"
#

/*!40000 ALTER TABLE `lakego_lakego_auth_rule` DISABLE KEYS */;
/*!40000 ALTER TABLE `lakego_lakego_auth_rule` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_auth_rule_access"
#

DROP TABLE IF EXISTS `lakego_lakego_auth_rule_access`;
CREATE TABLE `lakego_lakego_auth_rule_access` (
  `group_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `rule_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  UNIQUE KEY `rule_id` (`rule_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='用户组与权限关联表';

#
# Data for table "lakego_lakego_auth_rule_access"
#

/*!40000 ALTER TABLE `lakego_lakego_auth_rule_access` DISABLE KEYS */;
/*!40000 ALTER TABLE `lakego_lakego_auth_rule_access` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_rules"
#

DROP TABLE IF EXISTS `lakego_lakego_rules`;
CREATE TABLE `lakego_lakego_rules` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=COMPACT;

#
# Data for table "lakego_lakego_rules"
#

/*!40000 ALTER TABLE `lakego_lakego_rules` DISABLE KEYS */;
/*!40000 ALTER TABLE `lakego_lakego_rules` ENABLE KEYS */;
