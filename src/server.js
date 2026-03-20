const express = require('express');
const { execSync } = require('child_process');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== Basic認証 =====
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'haregake2026!';

function basicAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Panel"');
    return res.status(401).send('認証が必要です');
  }
  const decoded = Buffer.from(auth.split(' ')[1], 'base64').toString();
  const [user, pass] = decoded.split(':');
  if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  res.setHeader('WWW-Authenticate', 'Basic realm="Admin Panel"');
  return res.status(401).send('認証に失敗しました');
}
app.use(basicAuth);

// ===== ホストコマンド実行ヘルパー =====
function hostExec(cmd) {
  return execSync(`nsenter -t 1 -m -u -i -n -- bash -c "${cmd.replace(/"/g, '\\"')}"`, {
    encoding: 'utf-8',
    timeout: 15000,
  }).trim();
}

// ===== API: ユーザー一覧 =====
app.get('/api/users', (req, res) => {
  try {
    let passwdLines = '';
    try {
      passwdLines = hostExec("getent passwd | grep '^user_'");
    } catch (e) {
      return res.json([]);
    }

    const users = [];
    if (!passwdLines) return res.json([]);

    for (const line of passwdLines.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split(':');
      const username = parts[0];
      const uid = parts[2];
      const homeDir = parts[5];

      let groups = '';
      try { groups = hostExec(`groups ${username}`).split(':').pop().trim(); } catch (e) { /* ignore */ }

      let hasKey = false;
      try {
        const keyContent = hostExec(`cat ${homeDir}/.ssh/authorized_keys 2>/dev/null`);
        hasKey = keyContent.length > 10;
      } catch (e) { /* ignore */ }

      let ownedDirs = [];
      try {
        const dirs = hostExec(`find /var/www/app -maxdepth 1 -mindepth 1 -user ${username} -type d 2>/dev/null`);
        if (dirs) ownedDirs = dirs.split('\n').map(d => d.replace('/var/www/app/', ''));
      } catch (e) { /* ignore */ }

      let inSandbox = false;
      try {
        const members = hostExec('getent group sandbox_users');
        inSandbox = members.includes(username);
      } catch (e) { /* ignore */ }

      let locked = false;
      try {
        const status = hostExec(`passwd -S ${username}`);
        locked = status.includes(' L ') || status.includes(' LK ');
      } catch (e) { /* ignore */ }

      // sudo権限チェック
      let hasSudo = false;
      try {
        const sudoers = hostExec(`groups ${username}`);
        hasSudo = sudoers.includes('sudo') || sudoers.includes('admin');
      } catch (e) { /* ignore */ }

      // dockerグループチェック
      let hasDocker = false;
      try {
        const dockerMembers = hostExec('getent group docker');
        hasDocker = dockerMembers.includes(username);
      } catch (e) { /* ignore */ }

      users.push({
        username, uid, homeDir, groups,
        hasKey, ownedDirs, inSandbox, locked,
        hasSudo, hasDocker,
        createdLabel: locked ? 'パスワードロック済（鍵認証のみ）' : 'パスワード有効'
      });
    }
    res.json(users);
  } catch (e) {
    console.error('GET /api/users error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===== API: ユーザー作成 =====
app.post('/api/users', (req, res) => {
  try {
    let { name } = req.body;
    if (!name || !/^[a-zA-Z][a-zA-Z0-9_]{0,29}$/.test(name)) {
      return res.status(400).json({ error: '名前は英数字とアンダースコアのみ（先頭は英字、30文字以内）' });
    }

    const username = name.startsWith('user_') ? name : `user_${name}`;

    try {
      hostExec(`id ${username}`);
      return res.status(400).json({ error: `${username} は既に存在します` });
    } catch (e) { /* ユーザーが存在しない → OK */ }

    hostExec(`useradd -m -s /bin/bash ${username}`);
    hostExec(`passwd -l ${username}`);
    hostExec(`usermod -aG sandbox_users ${username}`);

    const keyDir = `/home/${username}/.ssh`;
    hostExec(`mkdir -p ${keyDir}`);
    hostExec(`ssh-keygen -t ed25519 -f ${keyDir}/id_ed25519 -N '' -C '${username}@haregake-lab'`);
    hostExec(`cp ${keyDir}/id_ed25519.pub ${keyDir}/authorized_keys`);
    hostExec(`chmod 700 ${keyDir}`);
    hostExec(`chmod 600 ${keyDir}/authorized_keys ${keyDir}/id_ed25519`);
    hostExec(`chmod 644 ${keyDir}/id_ed25519.pub`);
    hostExec(`chown -R ${username}:${username} ${keyDir}`);

    const privateKey = hostExec(`cat ${keyDir}/id_ed25519`);

    res.json({
      success: true,
      username,
      message: `${username} を作成しました`,
      privateKey,
    });
  } catch (e) {
    console.error('POST /api/users error:', e.message);
    res.status(500).json({ error: `作成失敗: ${e.message}` });
  }
});

// ===== API: ユーザー一括作成 =====
app.post('/api/users/bulk', (req, res) => {
  try {
    const { names } = req.body;
    if (!names || !Array.isArray(names) || names.length === 0) {
      return res.status(400).json({ error: '名前のリストを指定してください' });
    }
    if (names.length > 50) {
      return res.status(400).json({ error: '一度に作成できるのは50ユーザーまでです' });
    }

    const results = [];
    for (const rawName of names) {
      const name = rawName.trim();
      if (!name) continue;
      if (!/^[a-zA-Z][a-zA-Z0-9_]{0,29}$/.test(name)) {
        results.push({ name, success: false, error: '無効な名前（英数字・アンダースコアのみ、先頭は英字）' });
        continue;
      }

      const username = name.startsWith('user_') ? name : `user_${name}`;

      try {
        hostExec(`id ${username}`);
        results.push({ name, username, success: false, error: '既に存在します' });
        continue;
      } catch (e) { /* OK */ }

      try {
        hostExec(`useradd -m -s /bin/bash ${username}`);
        hostExec(`passwd -l ${username}`);
        hostExec(`usermod -aG sandbox_users ${username}`);

        const keyDir = `/home/${username}/.ssh`;
        hostExec(`mkdir -p ${keyDir}`);
        hostExec(`ssh-keygen -t ed25519 -f ${keyDir}/id_ed25519 -N '' -C '${username}@haregake-lab'`);
        hostExec(`cp ${keyDir}/id_ed25519.pub ${keyDir}/authorized_keys`);
        hostExec(`chmod 700 ${keyDir}`);
        hostExec(`chmod 600 ${keyDir}/authorized_keys ${keyDir}/id_ed25519`);
        hostExec(`chmod 644 ${keyDir}/id_ed25519.pub`);
        hostExec(`chown -R ${username}:${username} ${keyDir}`);

        const privateKey = hostExec(`cat ${keyDir}/id_ed25519`);
        results.push({ name, username, success: true, privateKey });
      } catch (e) {
        results.push({ name, username, success: false, error: e.message });
      }
    }

    const successCount = results.filter(r => r.success).length;
    const failCount = results.filter(r => !r.success).length;
    res.json({
      message: `${successCount} 件作成 / ${failCount} 件スキップ`,
      results,
    });
  } catch (e) {
    console.error('POST /api/users/bulk error:', e.message);
    res.status(500).json({ error: `一括作成失敗: ${e.message}` });
  }
});

// ===== API: ユーザー削除 =====
app.delete('/api/users/:username', (req, res) => {
  try {
    const { username } = req.params;
    if (!username.startsWith('user_')) {
      return res.status(400).json({ error: 'user_ プレフィックスのユーザーのみ削除可能です' });
    }
    hostExec(`userdel -r ${username}`);
    res.json({ success: true, message: `${username} を削除しました` });
  } catch (e) {
    console.error('DELETE /api/users error:', e.message);
    res.status(500).json({ error: `削除失敗: ${e.message}` });
  }
});

// ===== API: 秘密鍵の再取得 =====
app.get('/api/users/:username/key', (req, res) => {
  try {
    const { username } = req.params;
    const keyPath = `/home/${username}/.ssh/id_ed25519`;
    const privateKey = hostExec(`cat ${keyPath}`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${username}_id_ed25519"`);
    res.send(privateKey);
  } catch (e) {
    res.status(404).json({ error: '秘密鍵が見つかりません' });
  }
});

// ===== フロントエンド =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(3000, '0.0.0.0', () => {
  console.log('Admin panel running on :3000');
});
