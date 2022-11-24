DROP TABLE IF EXISTS `pre__action_log`;
CREATE TABLE `pre__action_log` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '日志id',
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
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `password` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_salt` char(6) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nickname` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `avatar` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
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
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `owner_id` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '关联类型id',
  `owner_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '附件关联类型',
  `name` mediumtext CHARACTER SET utf8mb4 NOT NULL COMMENT '文件名',
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

DROP TABLE IF EXISTS `pre__auth_group_access`;
CREATE TABLE `pre__auth_group_access` (
  `admin_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `group_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`admin_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `pre__auth_rule`;
CREATE TABLE `pre__auth_rule` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则id',
  `parentid` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '上级id',
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
  `group_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `rule_id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  UNIQUE KEY `rule_id` (`rule_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='用户组与权限关联表';

DROP TABLE IF EXISTS `pre__rules`;
CREATE TABLE `pre__rules` (
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

INSERT INTO `pre__admin` VALUES ('dbe97f21a69f67fb361b0be64988ee59','lakego','da3e31be10e21d4cb8d75b64d3e640e2','ANDsW2','lakego','lakego@admin.com','27511b7d9a20cb4696003e1147a5bb4a','lakego-admin 是基于 gin、JWT 和 RBAC 的 go 后台管理系统',0,1,0,'',1652759635,'127.0.0.1',1652587697,'127.0.0.1',1652545221,'127.0.0.1'),('e92ba0a3f86f4a5693d8487eb8c632b5','admin','1b65a57aeb44d988a1a5e713979daa76','QdHJdJ','管理员','lakego-admin@admin.com','7307e399ca9c1d2ade2a4d64606157c8','lakego-admin 是基于 gin、JWT 和 RBAC 的 go 后台管理系统',1,1,0,'',1669299869,'127.0.0.1',1652587697,'127.0.0.1',1652545221,'127.0.0.1');
INSERT INTO `pre__auth_group` VALUES ('538a712299e0ba6011aaf63f2a1317f4','0','超级管理员','拥有所有权限',95,1,1621431751,'127.0.0.1',1621431751,'127.0.0.1'),('5f3cf499d9d07ece255c2ca8e5a78296','0','编辑33','编辑的描述35',105,0,0,'',1631718553,'127.0.0.1');
INSERT INTO `pre__auth_rule` VALUES ('075543e098292a294892b8e70e77efee','8e9d66073a983c07cf4c86b2a710e6f3','数据库列表','/database','GET','lakego-admin.database.index','',100,1,0,'',1653574250,'127.0.0.1'),('09243babb819490ce6c40f6eeaa0025e','0e2a47aa358bdce70c829c52ec77ee99','修改个人信息详情','/profile','PUT','lakego-admin.profile.update','',100,1,0,'',1652666960,'127.0.0.1'),('098eab3ea7cb993c4333f74587790e5b','0','权限分组','#','OPTIONS','#','',100,1,0,'',1652666958,'127.0.0.1'),('09e9a12a6e71ba74979c50a3f430c31d','6882b68369f0ae1c6f56207fab896008','账号授权','/admin/{id}/access','PATCH','lakego-admin.admin.access','',100,1,0,'',1652666959,'127.0.0.1'),('0defb192855faf5cb8ca5363c911e039','ff689e618749620ce70428155336a43b','权限菜单更新','/auth/rule/{id}','PUT','lakego-admin.auth-rule.update','',100,1,0,'',1652666963,'127.0.0.1'),('0e02f8a195e1cbbf299e9fe74f92fbb4','098eab3ea7cb993c4333f74587790e5b','权限分组列表','/auth/group','GET','lakego-admin.auth-group.index','',100,1,0,'',1652666961,'127.0.0.1'),('0e2a47aa358bdce70c829c52ec77ee99','0','个人信息','#','OPTIONS','#','',100,1,0,'',1652666960,'127.0.0.1'),('16d5f2f0fddc47b6514b61b580d08400','ff689e618749620ce70428155336a43b','权限菜单详情','/auth/rule/{id}','GET','lakego-admin.auth-rule.detail','',100,1,0,'',1652666963,'127.0.0.1'),('179821f8b6e0da7e4ec4b1f4bc056149','6882b68369f0ae1c6f56207fab896008','账号权限同步','/admin/reset-permission','PUT','lakego-admin.admin.reset-permission','',200,1,0,'',1652666960,'127.0.0.1'),('1f92a9d133fffc0a015c3e9bc731b4fb','ff689e618749620ce70428155336a43b','权限菜单禁用','/auth/rule/{id}/disable','PATCH','lakego-admin.auth-rule.disable','',100,1,0,'',1652666962,'127.0.0.1'),('288fc97f55e20c4b20a51a2ab78dfd9c','8e9d66073a983c07cf4c86b2a710e6f3','优化数据表','/database/{name}/optimize','POST','lakego-admin.database.optimize','',100,1,0,'',1653574251,'127.0.0.1'),('2c73f962f88762e06cc4f36d8e56ec49','6882b68369f0ae1c6f56207fab896008','账号列表','/admin','GET','lakego-admin.admin.index','',100,1,0,'',1652666959,'127.0.0.1'),('310e1273080535c8d9449410525ee71e','6882b68369f0ae1c6f56207fab896008','账号启用','/admin/{id}/enable','PATCH','lakego-admin.admin.enable','',100,1,0,'',1652666961,'127.0.0.1'),('33c4639abf27a05c2ccd337155e13def','098eab3ea7cb993c4333f74587790e5b','权限分组删除','/auth/group/{id}','DELETE','lakego-admin.auth-group.delete','',100,1,0,'',1652666962,'127.0.0.1'),('3512c0eb086548154278823824fb03af','098eab3ea7cb993c4333f74587790e5b','权限分组禁用','/auth/group/{id}/disable','PATCH','lakego-admin.auth-group.disable','',100,1,0,'',1652666962,'127.0.0.1'),('36d11b500dd0b0006b98f9e2e72576f2','8bf3ccb7e0410379b6481c4e14cd7553','附件启用','/attachment/{id}/enable','PATCH','lakego-admin.attachment.enable','',154,1,0,'',1652666959,'127.0.0.1'),('3db97000d5000aaf09253dda63a2d0d0','8bf3ccb7e0410379b6481c4e14cd7553','附件删除','/attachment/{id}','DELETE','lakego-admin.attachment.delete','',153,1,0,'',1652666961,'127.0.0.1'),('402e983f828f31bdd72ea1c49c9170ea','ff689e618749620ce70428155336a43b','权限菜单删除','/auth/rule/{id}','DELETE','lakego-admin.auth-rule.delete','',100,1,0,'',1652666963,'127.0.0.1'),('43210266a5c8f4c73f5527d3ee845a8c','6882b68369f0ae1c6f56207fab896008','账号权限','/admin/{id}/rules','GET','lakego-admin.admin.rules','',100,1,0,'',1652666960,'127.0.0.1'),('4b532859fc64fd4cf95c031e93dd6cab','5739660965026ff5785bc520910286e7','清除 30 天前的日志数据','/action-log/clear','DELETE','lakego-admin.action-log.clear','',100,1,0,'',1652666962,'127.0.0.1'),('4f6561375a2a5af8f969275ff95e85ec','ff689e618749620ce70428155336a43b','权限菜单列表','/auth/rule','GET','lakego-admin.auth-rule.index','',100,1,0,'',1652666962,'127.0.0.1'),('5540d1faf9fd7f1930527f2f99e9c22f','5739660965026ff5785bc520910286e7','操作日志列表','/action-log','GET','lakego-admin.action-log.index','',100,1,0,'',1652666961,'127.0.0.1'),('5739660965026ff5785bc520910286e7','0','操作日志','#','OPTIONS','#','',100,1,0,'',1652666961,'127.0.0.1'),('5c24b10fc787c0e576563b2b3aabb7b1','098eab3ea7cb993c4333f74587790e5b','权限分组启用','/auth/group/{id}/enable','PATCH','lakego-admin.auth-group.enable','',100,1,0,'',1652666959,'127.0.0.1'),('5f9be186bf4a727b03cbdf16b8221aed','ca9e23822c0776a38b5aff3abf51fcf7','账号登陆','/passport/login','POST','lakego-admin.passport.login','',100,1,0,'',1652666962,'127.0.0.1'),('620e84d0916f8df0b8ea91cd6d9f013e','ff689e618749620ce70428155336a43b','权限菜单排序','/auth/rule/{id}/sort','PATCH','lakego-admin.auth-rule.sort','',100,1,0,'',1652666960,'127.0.0.1'),('640fe698c0abcd1408e56580bd121b73','8bf3ccb7e0410379b6481c4e14cd7553','附件下载','/attachment/download/{code}','GET','lakego-admin.attachment.download','',157,1,0,'',1652666962,'127.0.0.1'),('64ea470db2f27869e95e50d753e8e00f','6882b68369f0ae1c6f56207fab896008','修改账号头像','/admin/{id}/avatar','PATCH','lakego-admin.admin.avatar','',100,1,0,'',1652666962,'127.0.0.1'),('6882b68369f0ae1c6f56207fab896008','0','管理员','#','OPTIONS','#','',100,1,0,'',1652666959,'127.0.0.1'),('6b7c360a3c35fa52ea41a9546da137b2','ee0d96cd5b833a04a633cadab95c3ba9','权限 slug 列表','/system/rules','GET','lakego-admin.system.rules','',100,1,0,'',1652666960,'127.0.0.1'),('78ad02a839f5621028fcf29bc88fc557','8bf3ccb7e0410379b6481c4e14cd7553','附件禁用','/attachment/{id}/disable','PATCH','lakego-admin.attachment.disable','',155,1,0,'',1652666961,'127.0.0.1'),('80c033e05721227514f8544331751256','ca9e23822c0776a38b5aff3abf51fcf7','当前账号退出','/passport/logout','DELETE','lakego-admin.passport.logout','',100,1,0,'',1652666961,'127.0.0.1'),('817e806ceb1318996f9cdea88f8a7a67','ca9e23822c0776a38b5aff3abf51fcf7','刷新 token','/passport/refresh-token','POST','lakego-admin.passport.refresh-token','',100,1,0,'',1652666962,'127.0.0.1'),('828df90b4f56472b02fca89cc1257cd0','8bf3ccb7e0410379b6481c4e14cd7553','附件下载码','/attachment/downcode/{id}','GET','lakego-admin.attachment.downcode','',156,1,0,'',1652666959,'127.0.0.1'),('8bf3ccb7e0410379b6481c4e14cd7553','0','附件','#','OPTIONS','#','',100,1,0,'',1652666959,'127.0.0.1'),('8d237819676cbfed7245c824c3ae80ad','098eab3ea7cb993c4333f74587790e5b','权限分组添加','/auth/group','POST','lakego-admin.auth-group.create','',100,1,0,'',1652666961,'127.0.0.1'),('8e8c76db360033d1d1afef7f70164299','098eab3ea7cb993c4333f74587790e5b','权限分组更新','/auth/group/{id}','PUT','lakego-admin.auth-group.update','',100,1,0,'',1652666962,'127.0.0.1'),('8e9d66073a983c07cf4c86b2a710e6f3','0','数据库管理','#','OPTIONS','#','',100,1,0,'',1653574248,'127.0.0.1'),('93ee949695a29ea3b4e2a4f49432d057','098eab3ea7cb993c4333f74587790e5b','权限分组子列表','/auth/group/children','GET','lakego-admin.auth-group.children','',100,1,0,'',1652666962,'127.0.0.1'),('9f5d637795d31a71880fd10f88b47963','d3d58960e6078393ec2bd9b6fd80ddb6','首页信息','/example/index','GET','lakego-admin.example.index','',100,1,0,'',1652666959,'127.0.0.1'),('a08d614bcda670d9c26cca5df6308895','6882b68369f0ae1c6f56207fab896008','删除账号','/admin/{id}','DELETE','lakego-admin.admin.delete','',100,1,0,'',1652666959,'127.0.0.1'),('a2a42e932ec71697d7a6d4ff193b8b07','098eab3ea7cb993c4333f74587790e5b','权限分组详情','/auth/group/{id}','GET','lakego-admin.auth-group.detail','',100,1,0,'',1652666962,'127.0.0.1'),('a6ea9687d002ed430b15b1dae31b71e4','ff689e618749620ce70428155336a43b','权限菜单添加','/auth/rule','POST','lakego-admin.auth-rule.create','',100,1,0,'',1652666962,'127.0.0.1'),('a8728542900f3661f4d22cf781ff3b8a','6882b68369f0ae1c6f56207fab896008','账号详情','/admin/{id}','GET','lakego-admin.admin.detail','',100,1,0,'',1652666959,'127.0.0.1'),('ada780ca886b761381242a4c6547421e','6882b68369f0ae1c6f56207fab896008','账号禁用','/admin/{id}/disable','PATCH','lakego-admin.admin.disable','',100,1,0,'',1652666961,'127.0.0.1'),('ae3b04a373cde11c589f0ef8aef2aba8','0e2a47aa358bdce70c829c52ec77ee99','个人权限列表','/profile/rules','GET','lakego-admin.profile.rules','',100,1,0,'',1652666961,'127.0.0.1'),('b11f34c655770ad95121185c1908630a','ff689e618749620ce70428155336a43b','权限菜单树结构','/auth/rule/tree','GET','lakego-admin.auth-rule.tree','',100,1,0,'',1652666959,'127.0.0.1'),('b67a6fe87ce86b1605340750da69a800','8bf3ccb7e0410379b6481c4e14cd7553','附件详情','/attachment/{id}','GET','lakego-admin.attachment.detail','',152,1,0,'',1652666961,'127.0.0.1'),('b97e1968e90fe3951af8295287ded27f','0','上传','#','OPTIONS','#','',100,1,0,'',1652666961,'127.0.0.1'),('ba713d0e9832d4b633b2eb53623f234a','ee0d96cd5b833a04a633cadab95c3ba9','系统信息','/system/info','GET','lakego-admin.system.info','',100,1,0,'',1652666961,'127.0.0.1'),('bf326dd64b8e8a60048bba8246636818','6882b68369f0ae1c6f56207fab896008','添加账号所需分组','/admin/groups','GET','lakego-admin.admin.groups','',100,1,0,'',1652666961,'127.0.0.1'),('c5ad12acd10dded963373796d0df2751','098eab3ea7cb993c4333f74587790e5b','权限分组树结构','/auth/group/tree','GET','lakego-admin.auth-group.tree','',100,1,0,'',1652666962,'127.0.0.1'),('ca9e23822c0776a38b5aff3abf51fcf7','0','登陆相关','#','OPTIONS','#','',100,1,0,'',1652666960,'127.0.0.1'),('cb1a80836eb070922df0a31500ec2945','ff689e618749620ce70428155336a43b','权限菜单子列表','/auth/rule/children','GET','lakego-admin.auth-rule.children','',100,1,0,'',1652666962,'127.0.0.1'),('ceba5426275a3a6b87b3864c24b67ae2','6882b68369f0ae1c6f56207fab896008','更新账号','/admin/{id}','PUT','lakego-admin.admin.update','',100,1,0,'',1652666959,'127.0.0.1'),('d04d4b1913c0797e96eea263daadcca4','0e2a47aa358bdce70c829c52ec77ee99','修改个人头像','/profile/avatar','PATCH','lakego-admin.profile.avatar','',100,1,0,'',1652666961,'127.0.0.1'),('d1b913595597577d06637446363702d2','6882b68369f0ae1c6f56207fab896008','账号退出','/admin/logout/{refreshToken}','DELETE','lakego-admin.admin.logout','',100,1,0,'',1652666959,'127.0.0.1'),('d2d491bcf76fc688325df5a7ab8cc9e1','6882b68369f0ae1c6f56207fab896008','添加账号','/admin','POST','lakego-admin.admin.create','',100,1,0,'',1652666960,'127.0.0.1'),('d3d58960e6078393ec2bd9b6fd80ddb6','0','例子','#','OPTIONS','#','',100,1,0,'',1652666959,'127.0.0.1'),('d52122e266a455f5fffd7d67076aa839','098eab3ea7cb993c4333f74587790e5b','权限分组排序','/auth/group/{id}/sort','PATCH','lakego-admin.auth-group.sort','',100,1,0,'',1652666958,'127.0.0.1'),('d54d9382d06bd1c45892439fef69161b','8e9d66073a983c07cf4c86b2a710e6f3','修复数据表','/database/{name}/repair','POST','lakego-admin.database.repair','',100,1,0,'',1653574251,'127.0.0.1'),('d74630574f0f00b518ce206dd79dd4f6','8e9d66073a983c07cf4c86b2a710e6f3','数据库表详情','/database/{name}','GET','lakego-admin.database.detail','',100,1,0,'',1653574248,'127.0.0.1'),('d929dbf39a7890375040cbf950249150','ff689e618749620ce70428155336a43b','清空特定ID权限','/auth/rule/clear','DELETE','lakego-admin.auth-rule.clear','',100,1,0,'',1652666960,'127.0.0.1'),('d9ff12d14d89108d1a7fa82064513d8f','098eab3ea7cb993c4333f74587790e5b','权限分组授权','/auth/group/{id}/access','PATCH','lakego-admin.auth-group.access','',100,1,0,'',1652666960,'127.0.0.1'),('e425565db42e9d6a677b4aff6c4360fb','ff689e618749620ce70428155336a43b','权限菜单启用','/auth/rule/{id}/enable','PATCH','lakego-admin.auth-rule.enable','',100,1,0,'',1652666961,'127.0.0.1'),('e9c67d9bd1806fed47dac232239f0116','0e2a47aa358bdce70c829c52ec77ee99','修改密码','/profile/password','PATCH','lakego-admin.profile.password','',100,1,0,'',1652666962,'127.0.0.1'),('eaf9ab6114c24da475aead6c99f23780','ca9e23822c0776a38b5aff3abf51fcf7','登陆验证码','/passport/captcha','GET','lakego-admin.passport.captcha','',100,1,0,'',1652666962,'127.0.0.1'),('ee0d96cd5b833a04a633cadab95c3ba9','0','系统','#','OPTIONS','#','',100,1,0,'',1652666960,'127.0.0.1'),('eec6cc6f6b39460b42321fd46f09bf00','8bf3ccb7e0410379b6481c4e14cd7553','附件列表','/attachment','GET','lakego-admin.attachment.index','',151,1,0,'',1652666959,'127.0.0.1'),('f9440481c018c4f0a1509cdadb413ced','6882b68369f0ae1c6f56207fab896008','修改账号密码','/admin/{id}/password','PATCH','lakego-admin.admin.password','',100,1,0,'',1652666960,'127.0.0.1'),('f9daff960a4854c871f4b403cb5650bf','b97e1968e90fe3951af8295287ded27f','上传文件','/upload/file','POST','lakego-admin.upload.file','',100,1,0,'',1652666961,'127.0.0.1'),('fc0d7072871286a3a542ea2289a7344c','0e2a47aa358bdce70c829c52ec77ee99','个人信息详情','/profile','GET','lakego-admin.profile.index','',100,1,0,'',1652666960,'127.0.0.1'),('ff689e618749620ce70428155336a43b','0','权限菜单','#','OPTIONS','#','',100,1,0,'',1652666959,'127.0.0.1');