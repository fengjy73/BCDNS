create database if not exists bcdns;
use bcdns;

drop table if exists vc_record;
CREATE TABLE `vc_record` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `apply_no` varchar(50) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '申请编号',
  `content` LONGBLOB DEFAULT NULL COMMENT '申请内容',
  `credential_type` tinyint(1) DEFAULT NULL COMMENT '模板id',
  `status` tinyint(1) DEFAULT NULL COMMENT '申请状态（0待申请；1待审核 2已通过 3未通过 4已吊销）',
  `vc_id` varchar(100) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '凭证id',
  `vc_data` LONGBLOB DEFAULT NULL COMMENT '证书数据',
  `public_key` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'bid公钥',
  `owner_public_key` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '证书持有者公钥',
  `user_id` LONGBLOB DEFAULT NULL COMMENT '用户bid',
  `create_time` BigInt DEFAULT NULL COMMENT '创建时间',
  `update_time` BigInt DEFAULT NULL COMMENT '更新时间',
  `is_download` tinyint(1) DEFAULT '0' COMMENT '是否已下载（0-否；1-是)',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=COMPACT COMMENT='凭证记录表';

drop table if exists vc_root;
CREATE TABLE `vc_root` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vc_root` LONGBLOB DEFAULT NULL COMMENT '根证书'
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=COMPACT COMMENT='根证书记录表';

drop table if exists api_key_record;
CREATE TABLE `api_key_record` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `api_key` varchar(50) COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'api-key',
  `api_secret` varchar(50) COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'api-secret',
  `issuer_private_key` varchar(100) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '发证方私钥',
  `issuer_id` varchar(50) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '发证方id',
  `init_tag` tinyint(1) DEFAULT '0' COMMENT '是否已初始化（0-否；1-是)',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=COMPACT COMMENT='apikey记录表';

drop table if exists vc_audit;
CREATE TABLE `vc_audit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `apply_no` varchar(50) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '申请编号',
  `vc_id` varchar(100) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '凭证id',
  `status` tinyint(1) DEFAULT NULL COMMENT '申请状态（0待申请；1待审核 2已通过 3未通过 4已吊销）',
  `audit_id` LONGBLOB DEFAULT NULL COMMENT '发证方id',
  `vc_owner_id` LONGBLOB DEFAULT NULL COMMENT 'vc拥有者id',
  `reason` varchar(1024) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '备注',
  `create_time` BigInt DEFAULT NULL COMMENT '创建时间',
  `update_time` BigInt DEFAULT NULL COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=COMPACT COMMENT='审批记录表';



