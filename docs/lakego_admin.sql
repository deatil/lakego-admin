# Host: localhost  (Version: 5.5.53)
# Date: 2021-09-04 12:11:40
# Generator: MySQL-Front 5.3  (Build 4.234)

/*!40101 SET NAMES utf8 */;

#
# Structure for table "lakego_lakego_admin"
#

DROP TABLE IF EXISTS `lakego_lakego_admin`;
CREATE TABLE `lakego_lakego_admin` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_salt` char(6) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nickname` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `avatar` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `introduce` mediumtext COLLATE utf8mb4_unicode_ci,
  `is_root` tinyint(1) DEFAULT NULL,
  `status` tinyint(1) NOT NULL,
  `refresh_time` int(10) NOT NULL DEFAULT '0' COMMENT '刷新时间',
  `refresh_ip` varchar(50) CHARACTER SET utf8mb4 NOT NULL DEFAULT '' COMMENT '刷新IP',
  `last_active` int(10) DEFAULT NULL,
  `last_ip` varchar(50) CHARACTER SET utf8mb4 DEFAULT NULL,
  `update_time` int(10) DEFAULT NULL,
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `add_time` int(10) DEFAULT NULL,
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

#
# Data for table "lakego_lakego_admin"
#

/*!40000 ALTER TABLE `lakego_lakego_admin` DISABLE KEYS */;
INSERT INTO `lakego_lakego_admin` VALUES ('dbe97f21a69f67fb361b0be64988ee59','lakego','6b4ee75684079f24bb6331d6b4abbb57','bOMvXH','Lake','lake@qq.com','d0633455bf755b408cbc4a6b4fe2400c','lakego-admin',0,1,0,'',1621520922,'127.0.0.1',1621431650,'127.0.0.1',1564415458,'2130706433'),('e92ba0a3f86f4a5693d8487eb8c632b5','admin','db335c563a446ce5bb529a5b6edd0f55','yl2Apw','管理员','lake-admin@qq.com','eb73eb5d52f9c663b5809b6839f2f9a8','管理员',1,1,0,'',1621610257,'127.0.0.1',0,'0',1564667925,'2130706433');
/*!40000 ALTER TABLE `lakego_lakego_admin` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_attachment"
#

DROP TABLE IF EXISTS `lakego_lakego_attachment`;
CREATE TABLE `lakego_lakego_attachment` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `owner_id` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '关联类型ID',
  `owner_type` varchar(50) CHARACTER SET utf8mb4 DEFAULT '' COMMENT '附件关联类型',
  `name` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件名',
  `path` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件路径',
  `mime` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件mime类型',
  `extension` varchar(10) CHARACTER SET utf8mb4 NOT NULL DEFAULT '' COMMENT '文件类型',
  `size` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0' COMMENT '文件大小',
  `md5` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件md5',
  `sha1` char(40) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT 'sha1 散列值',
  `disk` varchar(16) CHARACTER SET utf8mb4 NOT NULL DEFAULT 'public' COMMENT '上传驱动',
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
INSERT INTO `lakego_lakego_attachment` VALUES ('a816799397e73f9b1978a9738f79a3c6','e92ba0a3f86f4a5693d8487eb8c632b5','admin','2.jpg','images/a816799397e73f9b1978a9738f79a3c6.jpg','image/jpeg','jpg','845941','8cd6239532a506d5b90b4652968b5d8f','da39a3ee5e6b4b0d3255bfef95601890afd80709','public',1,0,1630588690,1630588690,'127.0.0.1');
/*!40000 ALTER TABLE `lakego_lakego_attachment` ENABLE KEYS */;

#
# Structure for table "lakego_lakego_auth_group"
#

DROP TABLE IF EXISTS `lakego_lakego_auth_group`;
CREATE TABLE `lakego_lakego_auth_group` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `parentid` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
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
  `admin_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `group_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`admin_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

#
# Data for table "lakego_lakego_auth_group_access"
#

/*!40000 ALTER TABLE `lakego_lakego_auth_group_access` DISABLE KEYS */;
INSERT INTO `lakego_lakego_auth_group_access` VALUES ('e92ba0a3f86f4a5693d8487eb8c632b5','538a712299e0ba6011aaf63f2a1317f4');
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
INSERT INTO `lakego_lakego_rules` VALUES ('6912e5e9f8d33f51603a2ae0265cea48','g','user','editer','','','',''),('cfe1fdeb9a6cb0efbe905449d3448b74','p','editer','user/add','post','','','');
/*!40000 ALTER TABLE `lakego_lakego_rules` ENABLE KEYS */;
