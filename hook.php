<?php
require_once('class.GitHubHook.php');

// Initiate the GitHub Deployment Hook
$hook = new GitHubHook;

// Enable the debug log
$hook->enableDebug();

// Adding `prod` branch to deploy for `production` to path `/var/www/testhook/prod` limiting to only `user@gmail.com`
$hook->addBranch('master', 'Production-master', '/var/www/vhosts/backend-staging.com/httpdocs/');
$hook->addBranch('server-original', 'Original', '/var/www/vhosts/backend-staging.com/httpdocs/');

// Deploy the commits
$hook->deploy();