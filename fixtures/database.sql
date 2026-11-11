-- Synthetic mysqldump-style fixture for testing. No actual user accounts.
INSERT INTO `demo_users` VALUES (1,'knownadmin','hash','Known','known@example.invalid','','2026-01-01 00:00:00','',0,'Known'),(2,'mysteryadmin','hash','Mystery','unknown@example.invalid','','2026-11-09 00:00:00','',0,'Mystery');
INSERT INTO `demo_usermeta` (`umeta_id`,`user_id`,`meta_key`,`meta_value`) VALUES (1,1,'demo_capabilities','a:1:{s:13:"administrator";b:1;}'),(2,2,'demo_capabilities','a:1:{s:13:"administrator";b:1;}');
INSERT INTO `demo_options` (`option_id`,`option_name`,`option_value`,`autoload`) VALUES (42,'custom_footer','<script src="https://example.invalid/demo.js"></script>','yes');
