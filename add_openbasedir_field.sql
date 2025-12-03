-- SQL脚本：为子域名表添加openBasedir字段

-- 直接执行此SQL命令将在websiteFunctions_childdomains表中添加openBasedir字段
ALTER TABLE websiteFunctions_childdomains ADD COLUMN openBasedir INTEGER DEFAULT 0;

-- 执行完后，可以使用以下命令验证字段是否已添加
-- DESCRIBE websiteFunctions_childdomains;
