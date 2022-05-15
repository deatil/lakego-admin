DROP TABLE IF EXISTS `pre__action_log`;
CREATE TABLE `pre__action_log` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '日志ID',
  `name` varchar(250) CHARACTER SET utf8mb4 NOT NULL DEFAULT '' COMMENT '操作账号信息',
  `url` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `method` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '请求类型',
  `info` text COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '内容信息',
  `useragent` text COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'User-Agent',
  `time` int(10) DEFAULT NULL,
  `ip` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `status` char(3) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '输出状态',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=COMPACT COMMENT='操作日志';

DROP TABLE IF EXISTS `pre__admin`;
CREATE TABLE `pre__admin` (
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

DROP TABLE IF EXISTS `pre__attachment`;
CREATE TABLE `pre__attachment` (
  `id` char(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `owner_id` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '关联类型ID',
  `owner_type` varchar(50) CHARACTER SET utf8mb4 DEFAULT '' COMMENT '附件关联类型',
  `name` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件名',
  `path` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件路径',
  `mime` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '文件mime类型',
  `extension` varchar(15) CHARACTER SET utf8mb4 NOT NULL DEFAULT '' COMMENT '文件类型',
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
  `parentid` char(32) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '上级ID',
  `title` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '规则中文描述',
  `url` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' COMMENT '访问地址',
  `method` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'GET' COMMENT '请求类型',
  `slug` varchar(50) CHARACTER SET utf8mb4 NOT NULL DEFAULT '' COMMENT '地址鉴权标识',
  `description` varchar(255) CHARACTER SET utf8mb4 DEFAULT '' COMMENT '描述',
  `listorder` int(10) NOT NULL DEFAULT '100' COMMENT '排序ID',
  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态',
  `update_time` int(10) DEFAULT '0' COMMENT '更新时间',
  `update_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '0' COMMENT '更新IP',
  `add_time` int(10) DEFAULT '0' COMMENT '添加时间',
  `add_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT '' COMMENT '添加IP',
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

INSERT INTO `pre__admin` VALUES ('a1f47299eb1ef1ae137dad42f3fedc5f','admin223','','','admin22333','larke-admin22@qq.com','','说明11111',0,1,0,'',0,'',0,'',1631632660,'127.0.0.1'),('dbe97f21a69f67fb361b0be64988ee59','lakego','6b4ee75684079f24bb6331d6b4abbb57','bOMvXH','Lake','lake@qq.com','d0633455bf755b408cbc4a6b4fe2400c','lakego-admin',0,1,0,'',1621520922,'127.0.0.1',1621431650,'127.0.0.1',1564415458,'2130706433'),('e92ba0a3f86f4a5693d8487eb8c632b5','admin','db335c563a446ce5bb529a5b6edd0f55','yl2Apw','管理员','lake-admin@qq.com','78c9246a8c10eb2fe285915df5cc6bd8','管理员',1,1,0,'',1621610257,'127.0.0.1',0,'0',1564667925,'2130706433');
INSERT INTO `pre__auth_group` VALUES ('538a712299e0ba6011aaf63f2a1317f4','0','超级管理员','拥有所有权限',95,1,1621431751,'127.0.0.1',1621431751,'127.0.0.1'),('5f3cf499d9d07ece255c2ca8e5a78296','0','编辑33','编辑的描述35',105,0,0,'',1631718553,'127.0.0.1');
INSERT INTO `pre__auth_rule` VALUES ('0e3b77e60d575a9c1289cc613e283201','5aa6b93a1fde695da30d71168fb61f85','添加账号所需分组','/admin/groups','GET','lakego-admin.admin.groups','',106,1,1652282573,'127.0.0.1',1651938566,'127.0.0.1'),('116813fb6bf3bcb1cfafcd963f56cee5','0','权限分组列表','/auth/group','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('116813fb6bf3bcb1cfafcd963f56ceeb','116813fb6bf3bcb1cfafcd963f56cee5','权限分组列表','/auth/group','GET','lakego-admin.auth-group.index','',101,1,1652455286,'127.0.0.1',1651938565,'127.0.0.1'),('120e39fe9e287259a9f9b1e8f397ffdc','116813fb6bf3bcb1cfafcd963f56cee5','权限分组添加','/auth/group','POST','lakego-admin.auth-group.add','',103,1,1652455294,'127.0.0.1',1651938565,'127.0.0.1'),('19946afa96ee28548d88f6d3eafb16bb','5aa6b93a1fde695da30d71168fb61f85','账号权限','/admin/{id}/rules','GET','lakego-admin.admin.rules','',110,1,1652282612,'127.0.0.1',1651938566,'127.0.0.1'),('243a8efa7ba7726cc050767bd9d33171','eef6867301b9b3f9f5668607690962d5','权限菜单更新','/auth/rule/{id}','PUT','lakego-admin.auth-rule.update','',105,1,1652455434,'127.0.0.1',1651938564,'127.0.0.1'),('2522b6b5a3da71d919aa6608c2ad0ab8','975779b63f40041b224ad30eda04bfe5','附件下载码','/attachment/downcode/{id}','GET','lakego-admin.attachment.downcode','',100,1,1652455267,'127.0.0.1',1651938565,'127.0.0.1'),('2af45fee159ecada61a88655a2eb1230','9a628f3edacb29f05b6959014afbbc35','修改个人信息详情','/profile','PUT','lakego-admin.profile-save','',100,1,1652455378,'127.0.0.1',1651938565,'127.0.0.1'),('33136b1273dd691788ec0962351ba34d','116813fb6bf3bcb1cfafcd963f56cee5','权限分组删除','/auth/group/{id}','DELETE','lakego-admin.auth-group.delete','',108,1,1652455307,'127.0.0.1',1651938565,'127.0.0.1'),('3bd70658121f43ca1b3e1d5451e68a24','9a628f3edacb29f05b6959014afbbc35','个人权限列表','/profile/rules','GET','lakego-admin.profile-rules','',100,1,1652456667,'127.0.0.1',1651938567,'127.0.0.1'),('42d25f1edca8e93f460b3bcd17c39183','116813fb6bf3bcb1cfafcd963f56cee5','权限分组启用','/auth/group/{id}/enable','PATCH','lakego-admin.auth-group.enable','',109,1,1652282644,'127.0.0.1',1651938566,'127.0.0.1'),('43c163ef6730e4a90a9d7399f22d5959','975779b63f40041b224ad30eda04bfe5','附件详情','/attachment/{id}','GET','lakego-admin.attachment.detail','',100,1,1652282444,'127.0.0.1',1651938567,'127.0.0.1'),('48bc99f48a16e7311684fd70df416230','48bc99f48a16e7311684fd70df416235','系统信息','/system/info','GET','lakego-admin.system-info','',100,1,1652456677,'127.0.0.1',1651938567,'127.0.0.1'),('48bc99f48a16e7311684fd70df416235','0','系统信息','#','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('4a49357738b8e89b7f7bec395f0dd046','eef6867301b9b3f9f5668607690962d5','权限菜单详情','/auth/rule/{id}','GET','lakego-admin.auth-rule.detail','',106,1,1652455427,'127.0.0.1',1651938564,'127.0.0.1'),('4b960aec286d3346c7ab0a1e376d903a','5aa6b93a1fde695da30d71168fb61f85','修改账号头像','/admin/{id}/avatar','PATCH','lakego-admin.admin.avatar','',109,1,1652282603,'127.0.0.1',1651938566,'127.0.0.1'),('52038b7b035241a5900928b58d046940','48bc99f48a16e7311684fd70df416235','上传文件','/upload/file','POST','lakego-admin.upload-file','',100,1,1652456653,'127.0.0.1',1651938567,'127.0.0.1'),('5238a9866f8ea56e2f8d65c80d6e2a28','975779b63f40041b224ad30eda04bfe5','附件下载','/attachment/download/{code}','GET','lakego-admin.attachment.download','',100,1,1652282691,'127.0.0.1',1651938566,'127.0.0.1'),('5266d49b99b1d35b43969c5703cf0ffd','975779b63f40041b224ad30eda04bfe5','附件删除','/attachment/{id}','DELETE','lakego-admin.attachment.delete','',100,1,1652282452,'127.0.0.1',1651938567,'127.0.0.1'),('567255ee8cd5190a6464c26a99e510bb','eef6867301b9b3f9f5668607690962d5','权限菜单禁用','/auth/rule/{id}/disable','PATCH','lakego-admin.auth-rule.disable','',110,1,1652282745,'127.0.0.1',1651938565,'127.0.0.1'),('571e61e158338ef4e8583c83a880d6fa','eef6867301b9b3f9f5668607690962d5','权限菜单子列表','/auth/rule/children','GET','lakego-admin.auth-rule.children','',102,1,1652282545,'127.0.0.1',1651938566,'127.0.0.1'),('5aa6b93a1fde695da30d71168fb61f85','0','账号列表','/admin','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('5aa6b93a1fde695da30d71168fb61f8a','5aa6b93a1fde695da30d71168fb61f85','账号列表','/admin','GET','lakego-admin.admin.index','',101,1,1652282761,'127.0.0.1',1651938565,'127.0.0.1'),('5b79286c69f57bd2e482534ca43b12c2','eef6867301b9b3f9f5668607690962d5','清空特定ID权限','/auth/rule/clear','DELETE','lakego-admin.auth-rule.clear','',100,1,1652282498,'127.0.0.1',1651938566,'127.0.0.1'),('63222faec1d921ec09d2c92b5c1b8fa7','7ea44270b8e2b80c8468b5a76dcc3c85','清除 30 天前的日志数据','/action-log/clear','DELETE','lakego-admin.action-log.clear','',101,1,1652455412,'127.0.0.1',1651938565,'127.0.0.1'),('6561a84581eb26508f6abca7483b2878','5aa6b93a1fde695da30d71168fb61f85','账号启用','/admin/{id}/enable','PATCH','lakego-admin.admin.enable','',107,1,1652282362,'127.0.0.1',1651938567,'127.0.0.1'),('6febcd42acd4e48a3ccd6d7800e1b713','9a628f3edacb29f05b6959014afbbc35','登陆验证码','/passport/captcha','GET','lakego-admin.passport.captcha','',100,1,1652282753,'127.0.0.1',1651938565,'127.0.0.1'),('7cb3fff2f5240010d1119150f073237a','48bc99f48a16e7311684fd70df416235','权限 slug 列表','/system/rules','GET','lakego-admin.system-rules','',100,1,1652455398,'127.0.0.1',1651938565,'127.0.0.1'),('7ea44270b8e2b80c8468b5a76dcc3c85','0','操作日志列表','/action-log','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('7ea44270b8e2b80c8468b5a76dcc3c8c','7ea44270b8e2b80c8468b5a76dcc3c85','操作日志列表','/action-log','GET','lakego-admin.action-log.index','',100,1,1652282351,'127.0.0.1',1651938567,'127.0.0.1'),('8fad4c363aaa62b4349c142c763522ed','9a628f3edacb29f05b6959014afbbc35','当前账号退出','/passport/logout','DELETE','lakego-admin.passport.logout','',100,1,1652282510,'127.0.0.1',1651938566,'127.0.0.1'),('91927471da0790264f98f2f726ddf98b','5aa6b93a1fde695da30d71168fb61f85','账号授权','/admin/{id}/access','PATCH','lakego-admin.admin.access','',111,1,1652282659,'127.0.0.1',1651938566,'127.0.0.1'),('975779b63f40041b224ad30eda04bfe5','0','附件列表','/attachment','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('975779b63f40041b224ad30eda04bfea','975779b63f40041b224ad30eda04bfe5','附件列表','/attachment','GET','lakego-admin.attachment.index','',100,1,1652282372,'127.0.0.1',1651938567,'127.0.0.1'),('9a628f3edacb29f05b6959014afbbc35','0','个人信息','/profile','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('9a628f3edacb29f05b6959014afbbc3e','9a628f3edacb29f05b6959014afbbc35','个人信息详情','/profile','GET','lakego-admin.profile','',100,1,1652455365,'127.0.0.1',1651938565,'127.0.0.1'),('9f97d09b2c4d2c4e0fe9e1839e3cb254','5aa6b93a1fde695da30d71168fb61f85','添加账号','/admin','POST','lakego-admin.admin.add','',102,1,1652455255,'127.0.0.1',1651938565,'127.0.0.1'),('a2cb53ae18482940b42c51a614a03f2c','eef6867301b9b3f9f5668607690962d5','权限菜单添加','/auth/rule','POST','lakego-admin.auth-rule.add','',104,1,1652455354,'127.0.0.1',1651938565,'127.0.0.1'),('a4e9c9a897efa133923555bdc76d18a9','9a628f3edacb29f05b6959014afbbc35','修改个人头像','/profile/avatar','PATCH','lakego-admin.profile-avatar','',100,1,1652282730,'127.0.0.1',1651938566,'127.0.0.1'),('a8bb135745cf42e86405dce0fb8b8c33','116813fb6bf3bcb1cfafcd963f56cee5','权限分组详情','/auth/group/{id}','GET','lakego-admin.auth-group.detail','',107,1,1652455317,'127.0.0.1',1651938565,'127.0.0.1'),('a968345612c3c735eff07fc14cc22e4b','5aa6b93a1fde695da30d71168fb61f85','删除账号','/admin/{id}','DELETE','lakego-admin.admin.delete','',105,1,1652282437,'127.0.0.1',1651938567,'127.0.0.1'),('adc6c3a9a722a870b233006b518814c4','975779b63f40041b224ad30eda04bfe5','附件禁用','/attachment/{id}/disable','PATCH','lakego-admin.attachment.disable','',100,1,1652282459,'127.0.0.1',1651938567,'127.0.0.1'),('b22ac56f76aeac429942c535b3773ab4','9a628f3edacb29f05b6959014afbbc35','修改密码','/profile/password','PATCH','lakego-admin.profile-password','',100,1,1652282407,'127.0.0.1',1651938567,'127.0.0.1'),('b4fb9f58cbad8aa086b933d5f7879f00','5aa6b93a1fde695da30d71168fb61f85','账号禁用','/admin/{id}/disable','PATCH','lakego-admin.admin.disable','',108,1,1652282674,'127.0.0.1',1651938566,'127.0.0.1'),('b99ff466b0e179aa3caa5594af102f45','5aa6b93a1fde695da30d71168fb61f85','账号权限同步','/admin/reset-permission','PUT','lakego-admin.admin.reset-permission','',115,1,1652282652,'127.0.0.1',1651938566,'127.0.0.1'),('c00fd9577a15065b2d469e01ea41958e','116813fb6bf3bcb1cfafcd963f56cee5','权限分组子列表','/auth/group/children','GET','lakego-admin.auth-group.children','',106,1,1652282708,'127.0.0.1',1651938566,'127.0.0.1'),('c714a2ef823260b647364f263066a939','9a628f3edacb29f05b6959014afbbc35','刷新 token','/passport/refresh-token','POST','lakego-admin.passport.refresh-token','',100,1,1652282520,'127.0.0.1',1651938566,'127.0.0.1'),('c83959f065d8d39914b25027e4f7876d','0','例子首页信息','/example/index','GET','lakego-admin.example.index','',100,1,1652455509,'127.0.0.1',1651938567,'127.0.0.1'),('cfdeb7dde5d2218a00cc640dacbb3d1f','9a628f3edacb29f05b6959014afbbc35','账号登陆','/passport/login','POST','lakego-admin.passport.login','',100,1,1652282397,'127.0.0.1',1651938567,'127.0.0.1'),('d2f4c037789d5efdf9a60d9bad445ca2','116813fb6bf3bcb1cfafcd963f56cee5','权限分组授权','/auth/group/{id}/access','PATCH','lakego-admin.auth-group.access','',111,1,1652282633,'127.0.0.1',1651938566,'127.0.0.1'),('d4990e595b80dc0de7f5b45a211ba4f7','eef6867301b9b3f9f5668607690962d5','权限菜单树结构','/auth/rule/tree','GET','lakego-admin.auth-rule.tree','',103,1,1652282557,'127.0.0.1',1651938566,'127.0.0.1'),('dd209dd136553a1c9635499e74c5583a','116813fb6bf3bcb1cfafcd963f56cee5','权限分组树结构','/auth/group/tree','GET','lakego-admin.auth-group.tree','',102,1,1652282471,'127.0.0.1',1651938567,'127.0.0.1'),('e24cdfff367df25064e2a5d55b38c76d','116813fb6bf3bcb1cfafcd963f56cee5','权限分组禁用','/auth/group/{id}/disable','PATCH','lakego-admin.auth-group.disable','',110,1,1652456645,'127.0.0.1',1652279060,'127.0.0.1'),('e2702a4782962bccceb0245491047214','5aa6b93a1fde695da30d71168fb61f85','更新账号','/admin/{id}','PUT','lakego-admin.admin.update','',104,1,1652282426,'127.0.0.1',1651938567,'127.0.0.1'),('e94ca74be59e97fb0b4fc103e580d140','5aa6b93a1fde695da30d71168fb61f85','账号详情','/admin/{id}','GET','lakego-admin.admin.detail','',103,1,1652282417,'127.0.0.1',1651938567,'127.0.0.1'),('ed3880f7ea1718b47e1d4eaf5fc90daf','eef6867301b9b3f9f5668607690962d5','权限菜单启用','/auth/rule/{id}/enable','PATCH','lakego-admin.auth-rule.enable','',109,1,1652282482,'127.0.0.1',1651938567,'127.0.0.1'),('edec007339338e9d18ba034b6588f491','eef6867301b9b3f9f5668607690962d5','权限菜单排序','/auth/rule/{id}/sort','PATCH','lakego-admin.auth-rule.sort','',108,1,1652282386,'127.0.0.1',1651938567,'127.0.0.1'),('ee71c26917b41ef613135c11ae41a16a','116813fb6bf3bcb1cfafcd963f56cee5','权限分组更新','/auth/group/{id}','PUT','lakego-admin.auth-group.update','',104,1,1652455327,'127.0.0.1',1651938565,'127.0.0.1'),('eef6867301b9b3f9f5668607690962d5','0','权限菜单列表','/auth/rule','HEAD','','',100,1,0,'',1652279248,'127.0.0.1'),('eef6867301b9b3f9f5668607690962d7','eef6867301b9b3f9f5668607690962d5','权限菜单列表','/auth/rule','GET','lakego-admin.auth-rule.index','',101,1,1652455347,'127.0.0.1',1651938565,'127.0.0.1'),('f12292951bc0565c98131fe2728582a4','975779b63f40041b224ad30eda04bfe5','附件启用','/attachment/{id}/enable','PATCH','lakego-admin.attachment.enable','',100,1,1652282619,'127.0.0.1',1651938566,'127.0.0.1'),('f8c8d9dfeaaa52f778ff01f957a47a4d','eef6867301b9b3f9f5668607690962d5','权限菜单删除','/auth/rule/{id}','DELETE','lakego-admin.auth-rule.delete','',107,1,1652282738,'127.0.0.1',1651938565,'127.0.0.1'),('fb3b6cf6ef30562c610afc0901b8e4e9','5aa6b93a1fde695da30d71168fb61f85','修改账号密码','/admin/{id}/password','PATCH','lakego-admin.admin.password','',112,1,1652282684,'127.0.0.1',1651938566,'127.0.0.1'),('fbf4ccc72acf9b1385c067bea8861f3b','5aa6b93a1fde695da30d71168fb61f85','账号退出','/admin/logout/{refreshToken}','DELETE','lakego-admin.admin.logout','',113,1,1652282587,'127.0.0.1',1651938566,'127.0.0.1'),('fd12b6af92913a64988bbd38b746682a','116813fb6bf3bcb1cfafcd963f56cee5','权限分组排序','/auth/group/{id}/sort','PATCH','lakego-admin.auth-group.sort','',108,1,1652455419,'127.0.0.1',1651938565,'127.0.0.1');
