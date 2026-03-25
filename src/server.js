const express = require('express');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
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

// ===== SMTP設定 =====
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const SERVER_IP = process.env.SERVER_IP || '160.16.207.196';

let transporter = null;
if (SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  console.log(`SMTP設定済み: ${SMTP_USER}`);
} else {
  console.log('SMTP未設定: メール送信は無効です');
}

// ===== ホストコマンド実行 =====
function hostExec(cmd) {
  return execSync(`nsenter -t 1 -m -u -i -n -- bash -c "${cmd.replace(/"/g, '\\"')}"`, {
    encoding: 'utf-8', timeout: 15000,
  }).trim();
}

// ===== ユーザーデータ管理（メール紐付け） =====
const USER_DATA_FILE = '/data/users.json';

function loadUserData() {
  try {
    if (fs.existsSync(USER_DATA_FILE)) return JSON.parse(fs.readFileSync(USER_DATA_FILE, 'utf-8'));
  } catch (e) { console.error('loadUserData error:', e.message); }
  return {};
}
function saveUserData(data) {
  try {
    fs.mkdirSync(path.dirname(USER_DATA_FILE), { recursive: true });
    fs.writeFileSync(USER_DATA_FILE, JSON.stringify(data, null, 2));
  } catch (e) { console.error('saveUserData error:', e.message); }
}

// メールアドレス → ユーザー名
function emailToUsername(email) {
  const local = email.split('@')[0].toLowerCase();
  const sanitized = local.replace(/[.\-+]/g, '_').replace(/[^a-z0-9_]/g, '');
  return `user_${sanitized}`;
}

// ===== WireGuard設定管理 =====
const WG_CONF = '/etc/wireguard/wg0.conf';
const VPN_SUBNET = '10.0.0';
const VPN_SERVER_PORT = 51820;

// 次に使えるVPN IPを取得
function getNextVpnIp() {
  const userData = loadUserData();
  const usedIps = new Set();
  usedIps.add(1); // 10.0.0.1 = server
  usedIps.add(2); // 10.0.0.2 = admin

  for (const [, ud] of Object.entries(userData)) {
    if (ud.vpnIp) {
      const last = parseInt(ud.vpnIp.split('.').pop());
      if (last) usedIps.add(last);
    }
  }
  for (let i = 3; i <= 254; i++) {
    if (!usedIps.has(i)) return `${VPN_SUBNET}.${i}`;
  }
  throw new Error('VPN IPアドレスが枯渇しました（最大253クライアント）');
}

// WireGuardクライアント設定を生成してサーバーに登録
function createWgPeer(username, vpnIp) {
  // クライアント鍵ペア生成（ホスト上で実行）
  const privKey = hostExec('wg genkey');
  const pubKeyHost = hostExec(`echo '${privKey}' | wg pubkey`);
  const serverPubKey = hostExec('cat /etc/wireguard/server_public.key');

  // サーバーのwg0.confにPeer追加
  const peerBlock = `
# === ${username} ===
[Peer]
PublicKey = ${pubKeyHost}
AllowedIPs = ${vpnIp}/32`;

  hostExec(`echo '${peerBlock}' >> ${WG_CONF}`);

  // 実行中のWireGuardにも即時反映
  hostExec(`wg set wg0 peer ${pubKeyHost} allowed-ips ${vpnIp}/32`);

  // クライアント設定ファイルの内容を返す
  const clientConf = `[Interface]
PrivateKey = ${privKey}
Address = ${vpnIp}/24
DNS = 1.1.1.1

[Peer]
PublicKey = ${serverPubKey}
Endpoint = ${SERVER_IP}:${VPN_SERVER_PORT}
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25`;

  return { clientConf, pubKey: pubKeyHost };
}

// WireGuardからPeerを削除
function removeWgPeer(username, pubKey) {
  try {
    if (pubKey) {
      hostExec(`wg set wg0 peer ${pubKey} remove`);
    }
    // wg0.confからもブロックを削除
    hostExec(`sed -i '/# === ${username} ===/,/^$/d' ${WG_CONF}`);
  } catch (e) {
    console.error('removeWgPeer error:', e.message);
  }
}

// ===== Geminiプロンプト生成（VPN + SSH） =====
function generateGeminiPrompt(username, vpnIp) {
  return `あなたはITの完全な初心者を手取り足取りサポートする、とても親切で丁寧なアシスタントです。

これから、このユーザーがVPN接続→SSH接続でリモートサーバーにログインできるように、一歩ずつ案内してください。
ユーザーは技術的な知識がほとんどないため、「ターミナル」「コマンド」「VPN」などの用語も毎回丁寧に説明してください。

【このサーバーはVPN接続が必須です】
セキュリティのため、サーバーへのSSH接続にはVPN（WireGuard）の接続が必要です。
まずVPNを接続してから、SSHでログインする手順を案内してください。

【接続情報】
- VPN方式: WireGuard
- VPN設定ファイル: 添付の「${username}_wireguard.conf」
- VPN接続後のサーバーアドレス: 10.0.0.1
- このユーザーのVPN IP: ${vpnIp || '（設定ファイル参照）'}
- ユーザー名: ${username}
- 認証方式: SSH鍵認証（秘密鍵ファイルを使用）
- 秘密鍵ファイル名: ${username}_id_ed25519（このメールに添付）

【あなたの役割】
1. まずユーザーのOSを確認してください（Windows / Mac / Linux）
2. OSに応じた手順を、1ステップずつ丁寧に教えてください
3. 各ステップが完了したら「できました」と言ってもらい、次に進んでください
4. エラーが出た場合は、エラーメッセージを貼り付けてもらい、解決方法を教えてください
5. 専門用語が出てきたら、必ず簡単な言葉で説明を添えてください
6. コマンドを入力してもらう際は、コピペ可能な形で提示してください

=== パートA: VPN（WireGuard）の設定 ===

Step A1: WireGuardアプリのインストール
- Mac: App Storeを開いて「WireGuard」を検索してインストール
  - または、ターミナルで brew install wireguard-tools（Homebrewが入っている場合）
- Windows: https://www.wireguard.com/install/ にアクセスして「Download Windows Installer」をクリック
  - ダウンロードしたファイルを実行してインストール
- 「WireGuardとは何か？」を簡潔に説明する（安全な通信トンネルを作るアプリ）

Step A2: VPN設定ファイルの読み込み
- このメールに添付されている「${username}_wireguard.conf」をダウンロード
- Mac（GUIアプリの場合）:
  - WireGuardアプリを開く
  - 左下の「+」ボタン →「ファイルからトンネルをインポート」
  - ダウンロードした「${username}_wireguard.conf」を選択
- Mac（CLIの場合）:
  - ターミナルで: sudo cp ~/Downloads/${username}_wireguard.conf /etc/wireguard/haregake.conf
- Windows:
  - WireGuardアプリを開く
  - 左下の「トンネルを追加」→「ファイルからトンネルをインポート」
  - ダウンロードした「${username}_wireguard.conf」を選択

Step A3: VPN接続
- Mac（GUIアプリ）: インポートしたトンネルを選択して「有効化」ボタンをクリック
- Mac（CLI）: ターミナルで sudo wg-quick up haregake
- Windows: インポートしたトンネルを選択して「有効化」ボタンをクリック
- 接続が成功すると、ステータスが「有効」（Active）に変わることを説明

Step A4: VPN接続確認
- ターミナルまたはPowerShellで: ping 10.0.0.1
- 「応答が返ってくれば成功！」と伝える
- もし応答がない場合のトラブルシューティング

=== パートB: SSH接続の設定 ===

Step B1: 秘密鍵ファイルの保存
- このメールに添付されている秘密鍵ファイル「${username}_id_ed25519」をダウンロード
- 保存先:
  - Mac: ~/.ssh/${username}_id_ed25519
  - Windows: C:\\Users\\（自分のユーザー名）\\.ssh\\${username}_id_ed25519
- ~/.ssh フォルダがない場合の作成方法も教える

Step B2: .ssh フォルダの作成と秘密鍵の配置
- Mac/Linux: mkdir -p ~/.ssh && mv ~/Downloads/${username}_id_ed25519 ~/.ssh/
- Windows: PowerShellで mkdir $env:USERPROFILE\\.ssh（既にある場合はスキップ）、Move-Item でファイルを移動

Step B3: 秘密鍵のパーミッション設定
- Mac/Linux: chmod 600 ~/.ssh/${username}_id_ed25519
- Windows: 以下を1行ずつ丁寧に説明
  $keyPath = "$env:USERPROFILE\\.ssh\\${username}_id_ed25519"
  icacls $keyPath /inheritance:r
  icacls $keyPath /grant:r "$($env:USERNAME):(R)"

Step B4: SSH接続テスト（VPN接続中であること！）
- Mac/Linux: ssh -i ~/.ssh/${username}_id_ed25519 ${username}@10.0.0.1
- Windows: ssh -i $env:USERPROFILE\\.ssh\\${username}_id_ed25519 ${username}@10.0.0.1
- ⚠ 重要: 接続先は 10.0.0.1 です（VPN経由のアドレス）
- 初回接続時の「The authenticity of host...」メッセージ → 「yes」を入力

Step B5: 接続確認
- 「${username}@...」のようなプロンプトが表示されたら成功！
- whoami コマンドで自分のユーザー名を確認
- 「おめでとうございます！VPN + SSH接続成功です！」と祝福する

Step B6: SSH config の設定（便利設定）
- 一度切断してから設定する（exit コマンド）
- Mac/Linux: nano ~/.ssh/config で以下を書き込む:
  Host haregake
    HostName 10.0.0.1
    User ${username}
    IdentityFile ~/.ssh/${username}_id_ed25519
- Windows: notepad $env:USERPROFILE\\.ssh\\config で同じ内容を書き込む
- 設定後は「ssh haregake」だけで接続できることを伝え、試してもらう

Step B7: 切断方法
- SSH切断: exit コマンドまたは Ctrl+D
- VPN切断:
  - Mac（GUI）: WireGuardアプリで「無効化」
  - Mac（CLI）: sudo wg-quick down haregake
  - Windows: WireGuardアプリで「無効化」

=== 毎回の接続手順まとめ ===
ユーザーに最後にこう伝える:
「今後サーバーに接続するときは、毎回この順番で行います:
 1. WireGuardアプリでVPNを接続（有効化）
 2. ターミナルで ssh haregake
 3. 作業が終わったら exit でSSH切断
 4. WireGuardアプリでVPNを切断（無効化）」

最初の一言は以下のように始めてください：
「こんにちは！サーバーへの接続設定をお手伝いします😊 このサーバーはセキュリティのためVPN接続が必要ですが、一つずつ進めれば大丈夫です！まず教えてください、お使いのパソコンは Windows ですか？ Mac ですか？」`;
}

// ===== メール本文生成（VPN対応版） =====
function generateEmailContent(username) {
  const userData = loadUserData();
  const ud = userData[username] || {};
  const vpnIp = ud.vpnIp || '';
  const prompt = generateGeminiPrompt(username, vpnIp);
  return `${username} 様

haregake-lab のサーバーアカウントが作成されました。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ あなたの接続情報
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ユーザー名       : ${username}
VPN IP           : ${vpnIp}
SSH接続先        : 10.0.0.1（VPN接続後）
認証方式         : SSH鍵認証

■ 添付ファイル（2つ）
  1. ${username}_wireguard.conf → VPN設定ファイル
  2. ${username}_id_ed25519     → SSH秘密鍵ファイル

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ 接続の流れ（概要）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
このサーバーはセキュリティのため VPN接続が必須 です。

【ステップ1】WireGuardアプリをインストール
【ステップ2】添付の VPN設定ファイル を読み込んでVPN接続
【ステップ3】VPN接続した状態で SSH接続

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ 設定が初めての方へ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
以下のプロンプトを丸ごとコピーして
Google Gemini ( https://gemini.google.com ) に貼り付けてください。
Geminiが一歩ずつ丁寧にガイドしてくれます。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ Gemini用プロンプト（以下を全てコピーして貼り付け）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${prompt}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ サーバー上で使えるディレクトリ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/var/www/app/sandbox/ → 共有実験エリア（自由に使えます）

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ アプリのアップロード方法（GitHub経由）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
作ったアプリをサーバーに公開するには、GitHub経由で行います。

【初回の手順】
1. GitHubにリポジトリを作成し、アプリのコードをpush
2. VPN接続 → SSH接続（ssh haregake）
3. サーバー上で以下を実行:
   cd /var/www/app/sandbox/
   git clone https://github.com/あなたのユーザー名/リポジトリ名.git 自分の名前
4. 管理者に「デプロイお願いします」と連絡

【2回目以降の更新】
1. ローカルで git add . → git commit → git push
2. VPN接続 → SSH接続
3. cd /var/www/app/sandbox/自分の名前 && git pull
4. 管理者にデプロイ依頼

※ 初めての方は下記のGeminiプロンプトもご利用ください。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ アップロード用 Geminiプロンプト
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSH接続ができるようになったら、以下も
Google Gemini に貼り付けて使ってください。

--- ここからコピー ---

あなたはITの完全な初心者を手取り足取りサポートする、とても親切で丁寧なアシスタントです。

このユーザーは、自分のPCで作ったWebアプリ（Claude Codeで作成）を、GitHub経由でリモートサーバーにアップロードしたいです。一歩ずつ丁寧に案内してください。

【前提条件】
- サーバーへのSSH接続は設定済み（ssh haregake で接続可能）
- VPN接続も設定済み（WireGuardで接続してからSSHする）
- アップロード先: /var/www/app/sandbox/
- サーバーアドレス: 10.0.0.1（VPN経由）
- ユーザー名: ${username}
- sudoやdockerコマンドは使えません
- アップロード後のデプロイ（公開）は管理者が行います

【あなたの役割】
1. ユーザーのOSを確認（Windows / Mac）
2. GitHubアカウント有無を確認。なければ作成を案内
3. 1ステップずつ教え、完了を確認してから次へ
4. エラーが出たら貼り付けてもらい解決
5. 専門用語は必ず簡単に説明（リポジトリ＝プロジェクトの保管場所 等）

【教えるべき手順】

Part 1: GitHubにコードをアップ

Step 1: GitHubアカウント確認
- https://github.com にアカウントがあるか確認
- なければアカウント作成を案内

Step 2: GitHubに新しいリポジトリを作成
- https://github.com/new にアクセス
- リポジトリ名を入力（例: my-first-app）
- Publicを選択 → Create repository

Step 3: Gitの初期設定（初回のみ）
- git --version でインストール確認
- なければインストール案内
  Mac: brew install git
  Windows: https://git-scm.com/download/win
- git config --global user.name "名前"
- git config --global user.email "メール"

Step 4: コードをGitHubにpush
- アプリフォルダに cd で移動
- git init
- git add .
- git commit -m "初回アップロード"
- git branch -M main
- git remote add origin https://github.com/ユーザー名/リポジトリ名.git
- git push -u origin main
- 認証が求められたらブラウザ認証を案内

Part 2: サーバーにダウンロード

Step 5: VPN接続 → WireGuardで有効化

Step 6: SSH接続 → ssh haregake

Step 7: サーバー上にアプリを配置
- cd /var/www/app/sandbox/
- git clone https://github.com/ユーザー名/リポジトリ名.git 自分の名前
- ls 自分の名前/ で確認

Step 8: 管理者に連絡
- 「sandboxにアプリを置きました。デプロイお願いします」とSlack等で連絡

Step 9: 切断 → exit → VPN無効化

【2回目以降の更新も教える】
ローカル: git add . → git commit -m "変更メモ" → git push
サーバー: ssh haregake → cd /var/www/app/sandbox/自分の名前 → git pull → exit
→ 管理者にデプロイ依頼

最初の一言：
「こんにちは！アプリのアップロードをお手伝いします😊 GitHubを使ってサーバーに公開します。一つずつ進めましょう！まず教えてください：
1. WindowsですかMacですか？
2. GitHubのアカウントは持っていますか？（https://github.com）
3. アップロードしたいアプリのフォルダはどこにありますか？」

--- ここまでコピー ---

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ 毎回の接続手順
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. WireGuardアプリでVPNを「有効化」
2. ターミナルで ssh haregake
3. 作業が終わったら exit → VPNを「無効化」

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ご不明点があれば管理者にお問い合わせください。

haregake-lab 管理者
`;
}

// ===== SMTP状態確認 =====
app.get('/api/smtp-status', (req, res) => {
  res.json({ configured: !!transporter, user: SMTP_USER || null });
});

// ===== API: ユーザー一覧 =====
app.get('/api/users', (req, res) => {
  try {
    const userData = loadUserData();
    let passwdLines = '';
    try { passwdLines = hostExec("getent passwd | grep '^user_'"); } catch (e) { return res.json([]); }

    const users = [];
    if (!passwdLines) return res.json([]);

    for (const line of passwdLines.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split(':');
      const username = parts[0];
      const uid = parts[2];
      const homeDir = parts[5];

      let groups = '';
      try { groups = hostExec(`groups ${username}`).split(':').pop().trim(); } catch (e) {}

      let hasKey = false;
      try {
        const keyContent = hostExec(`cat ${homeDir}/.ssh/authorized_keys 2>/dev/null`);
        hasKey = keyContent.length > 10;
      } catch (e) {}

      let ownedDirs = [];
      try {
        const dirs = hostExec(`find /var/www/app -maxdepth 1 -mindepth 1 -user ${username} -type d 2>/dev/null`);
        if (dirs) ownedDirs = dirs.split('\n').map(d => d.replace('/var/www/app/', ''));
      } catch (e) {}

      let inSandbox = false;
      try {
        const members = hostExec('getent group sandbox_users');
        inSandbox = members.includes(username);
      } catch (e) {}

      let locked = false;
      try {
        const status = hostExec(`passwd -S ${username}`);
        locked = status.includes(' L ') || status.includes(' LK ');
      } catch (e) {}

      let hasSudo = false;
      try {
        const g = hostExec(`groups ${username}`);
        hasSudo = g.includes('sudo') || g.includes(' admin');
      } catch (e) {}

      let hasDocker = false;
      try {
        const dm = hostExec('getent group docker');
        hasDocker = dm.includes(username);
      } catch (e) {}

      // ユーザーデータからメール情報を取得
      const ud = userData[username] || {};

      users.push({
        username, uid, homeDir, groups,
        hasKey, ownedDirs, inSandbox, locked,
        hasSudo, hasDocker,
        email: ud.email || null,
        emailSentAt: ud.emailSentAt || null,
        vpnIp: ud.vpnIp || null,
        hasVpn: !!ud.wgConf,
      });
    }
    res.json(users);
  } catch (e) {
    console.error('GET /api/users error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===== API: ユーザー作成（メールアドレスベース） =====
app.post('/api/users', (req, res) => {
  try {
    const { email, name } = req.body;

    let username;
    let userEmail = null;

    if (email) {
      // メールアドレスから自動生成
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: '有効なメールアドレスを入力してください' });
      }
      username = emailToUsername(email);
      userEmail = email;
    } else if (name) {
      // 従来の名前指定
      if (!/^[a-zA-Z][a-zA-Z0-9_]{0,29}$/.test(name)) {
        return res.status(400).json({ error: '名前は英数字とアンダースコアのみ（先頭は英字、30文字以内）' });
      }
      username = name.startsWith('user_') ? name : `user_${name}`;
    } else {
      return res.status(400).json({ error: 'メールアドレスまたは名前を入力してください' });
    }

    // 既存チェック
    try {
      hostExec(`id ${username}`);
      return res.status(400).json({ error: `${username} は既に存在します` });
    } catch (e) { /* OK */ }

    // ユーザー作成
    hostExec(`useradd -m -s /bin/bash ${username}`);
    hostExec(`passwd -l ${username}`);
    hostExec(`usermod -aG sandbox_users ${username}`);

    // SSH鍵生成
    const keyDir = `/home/${username}/.ssh`;
    hostExec(`mkdir -p ${keyDir}`);
    hostExec(`ssh-keygen -t ed25519 -f ${keyDir}/id_ed25519 -N '' -C '${username}@haregake-lab'`);
    hostExec(`cp ${keyDir}/id_ed25519.pub ${keyDir}/authorized_keys`);
    hostExec(`chmod 700 ${keyDir}`);
    hostExec(`chmod 600 ${keyDir}/authorized_keys ${keyDir}/id_ed25519`);
    hostExec(`chmod 644 ${keyDir}/id_ed25519.pub`);
    hostExec(`chown -R ${username}:${username} ${keyDir}`);

    const privateKey = hostExec(`cat ${keyDir}/id_ed25519`);

    // WireGuard設定生成
    const vpnIp = getNextVpnIp();
    let wgConf = '';
    let wgPubKey = '';
    try {
      const wgResult = createWgPeer(username, vpnIp);
      wgConf = wgResult.clientConf;
      wgPubKey = wgResult.pubKey;
    } catch (e) {
      console.error('WireGuard設定生成エラー:', e.message);
    }

    // ユーザーデータ保存
    const userData = loadUserData();
    userData[username] = {
      email: userEmail,
      createdAt: new Date().toISOString(),
      emailSentAt: null,
      vpnIp,
      wgPubKey,
      wgConf,
    };
    saveUserData(userData);

    res.json({ success: true, username, email: userEmail, vpnIp, message: `${username} を作成しました`, privateKey, wgConf });
  } catch (e) {
    console.error('POST /api/users error:', e.message);
    res.status(500).json({ error: `作成失敗: ${e.message}` });
  }
});

// ===== API: 一括作成 =====
app.post('/api/users/bulk', (req, res) => {
  try {
    const { entries } = req.body; // [{ email: "..." }, ...] or [{ name: "..." }, ...]
    if (!entries || !Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: '入力が空です' });
    }
    if (entries.length > 50) {
      return res.status(400).json({ error: '一度に作成できるのは50名までです' });
    }

    const results = [];
    const userData = loadUserData();

    for (const entry of entries) {
      const email = (entry.email || '').trim();
      const name = (entry.name || '').trim();
      if (!email && !name) continue;

      let username, userEmail = null;

      if (email) {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          results.push({ input: email, success: false, error: '無効なメールアドレス' });
          continue;
        }
        username = emailToUsername(email);
        userEmail = email;
      } else {
        const clean = name.replace(/^user_/, '');
        if (!/^[a-zA-Z][a-zA-Z0-9_]{0,29}$/.test(clean)) {
          results.push({ input: name, success: false, error: '無効な名前' });
          continue;
        }
        username = `user_${clean}`;
      }

      // 既存チェック
      try {
        hostExec(`id ${username}`);
        results.push({ input: email || name, username, success: false, error: '既に存在します' });
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

        // WireGuard設定生成
        const vpnIp = getNextVpnIp();
        let wgConf = '', wgPubKey = '';
        try {
          const wgResult = createWgPeer(username, vpnIp);
          wgConf = wgResult.clientConf;
          wgPubKey = wgResult.pubKey;
        } catch (e) { console.error('WG error:', e.message); }

        userData[username] = {
          email: userEmail,
          createdAt: new Date().toISOString(),
          emailSentAt: null,
          vpnIp, wgPubKey, wgConf,
        };

        results.push({ input: email || name, username, email: userEmail, vpnIp, success: true, privateKey, wgConf });
      } catch (e) {
        results.push({ input: email || name, username, success: false, error: e.message });
      }
    }

    saveUserData(userData);
    const ok = results.filter(r => r.success).length;
    const ng = results.filter(r => !r.success).length;
    res.json({ message: `${ok}件 作成 / ${ng}件 スキップ`, results });
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

    // WireGuard Peer削除
    const userData = loadUserData();
    const ud = userData[username];
    if (ud && ud.wgPubKey) {
      removeWgPeer(username, ud.wgPubKey);
    }

    // ユーザーデータからも削除
    delete userData[username];
    saveUserData(userData);

    res.json({ success: true, message: `${username} を削除しました` });
  } catch (e) {
    res.status(500).json({ error: `削除失敗: ${e.message}` });
  }
});

// ===== API: 秘密鍵ダウンロード =====
app.get('/api/users/:username/key', (req, res) => {
  try {
    const { username } = req.params;
    const privateKey = hostExec(`cat /home/${username}/.ssh/id_ed25519`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${username}_id_ed25519"`);
    res.send(privateKey);
  } catch (e) {
    res.status(404).json({ error: '秘密鍵が見つかりません' });
  }
});

// ===== API: VPN設定ダウンロード =====
app.get('/api/users/:username/vpn', (req, res) => {
  try {
    const { username } = req.params;
    const userData = loadUserData();
    const ud = userData[username];
    if (!ud || !ud.wgConf) {
      return res.status(404).json({ error: 'VPN設定が見つかりません' });
    }
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${username}_wireguard.conf"`);
    res.send(ud.wgConf);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: メールプレビュー =====
app.get('/api/users/:username/email-preview', (req, res) => {
  try {
    const { username } = req.params;
    const userData = loadUserData();
    const ud = userData[username];
    const email = ud ? ud.email : null;

    const subject = '【haregake-lab】サーバーアカウントが作成されました';
    const body = generateEmailContent(username);

    res.json({ subject, body, to: email, username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: メール送信 =====
app.post('/api/users/:username/send-email', (req, res) => {
  try {
    const { username } = req.params;
    const { customBody } = req.body; // 編集済み本文（オプション）

    if (!transporter) {
      return res.status(400).json({ error: 'SMTP が設定されていません。docker-compose.yml に SMTP_USER / SMTP_PASS を設定してください。' });
    }

    const userData = loadUserData();
    const ud = userData[username];
    if (!ud || !ud.email) {
      return res.status(400).json({ error: `${username} にメールアドレスが設定されていません` });
    }

    const subject = '【haregake-lab】サーバーアカウントが作成されました';
    const body = customBody || generateEmailContent(username);

    // 秘密鍵を添付ファイルとして
    let privateKey = '';
    try { privateKey = hostExec(`cat /home/${username}/.ssh/id_ed25519`); } catch(e) {}

    // 添付ファイル
    const attachments = [];
    if (privateKey) {
      attachments.push({ filename: `${username}_id_ed25519`, content: privateKey, contentType: 'text/plain' });
    }
    if (ud.wgConf) {
      attachments.push({ filename: `${username}_wireguard.conf`, content: ud.wgConf, contentType: 'text/plain' });
    }

    const mailOptions = {
      from: SMTP_FROM,
      to: ud.email,
      subject: subject,
      text: body,
      attachments,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('sendMail error:', err.message);
        return res.status(500).json({ error: `送信失敗: ${err.message}` });
      }

      // 送信日時を記録
      userData[username].emailSentAt = new Date().toISOString();
      saveUserData(userData);

      res.json({ success: true, message: `${ud.email} に送信しました` });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: 一括メール送信 =====
app.post('/api/users/bulk-send-email', (req, res) => {
  try {
    const { usernames } = req.body;
    if (!transporter) {
      return res.status(400).json({ error: 'SMTP が設定されていません' });
    }
    if (!usernames || !Array.isArray(usernames) || usernames.length === 0) {
      return res.status(400).json({ error: '送信先が指定されていません' });
    }

    const userData = loadUserData();
    const results = [];
    let pending = usernames.length;

    for (const username of usernames) {
      const ud = userData[username];
      if (!ud || !ud.email) {
        results.push({ username, success: false, error: 'メールアドレスなし' });
        pending--;
        if (pending === 0) done();
        continue;
      }

      const body = generateEmailContent(username);
      let privateKey = '';
      try { privateKey = hostExec(`cat /home/${username}/.ssh/id_ed25519`); } catch(e) {}

      const atts = [];
      if (privateKey) atts.push({ filename: `${username}_id_ed25519`, content: privateKey, contentType: 'text/plain' });
      if (ud.wgConf) atts.push({ filename: `${username}_wireguard.conf`, content: ud.wgConf, contentType: 'text/plain' });

      transporter.sendMail({
        from: SMTP_FROM,
        to: ud.email,
        subject: '【haregake-lab】サーバーアカウントが作成されました',
        text: body,
        attachments: atts,
      }, (err) => {
        if (err) {
          results.push({ username, email: ud.email, success: false, error: err.message });
        } else {
          userData[username].emailSentAt = new Date().toISOString();
          results.push({ username, email: ud.email, success: true });
        }
        pending--;
        if (pending === 0) done();
      });
    }

    function done() {
      saveUserData(userData);
      const ok = results.filter(r => r.success).length;
      res.json({ message: `${ok}/${results.length} 件送信完了`, results });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: ファイルブラウザ =====
const ALLOWED_ROOTS = ['/var/www/app', '/home'];

function isPathAllowed(p) {
  const resolved = path.resolve(p);
  return ALLOWED_ROOTS.some(root => resolved.startsWith(root));
}

app.get('/api/files', (req, res) => {
  try {
    const dir = req.query.path || '/var/www/app';
    if (!isPathAllowed(dir)) {
      return res.status(403).json({ error: 'このパスへのアクセスは許可されていません' });
    }

    const entries = [];
    let listing;
    try {
      listing = hostExec(`ls -la --time-style=long-iso ${dir} 2>/dev/null`);
    } catch (e) {
      return res.status(404).json({ error: 'ディレクトリが見つかりません' });
    }

    for (const line of listing.split('\n')) {
      if (line.startsWith('total') || !line.trim()) continue;
      // Parse ls -la output
      const parts = line.split(/\s+/);
      if (parts.length < 8) continue;
      const perms = parts[0];
      const owner = parts[2];
      const group = parts[3];
      const size = parseInt(parts[4]);
      const date = parts[5];
      const time = parts[6];
      const name = parts.slice(7).join(' ');

      if (name === '.' || name === '..') continue;

      const isDir = perms.startsWith('d');
      const isLink = perms.startsWith('l');
      const fullPath = path.join(dir, name.split(' -> ')[0]);

      entries.push({
        name: name.split(' -> ')[0],
        fullPath,
        isDir,
        isLink,
        perms,
        owner,
        group,
        size,
        modified: `${date} ${time}`,
        linkTarget: isLink ? (name.split(' -> ')[1] || '') : null,
      });
    }

    res.json({ path: dir, entries, parent: path.dirname(dir) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/files/read', (req, res) => {
  try {
    const filePath = req.query.path;
    if (!filePath || !isPathAllowed(filePath)) {
      return res.status(403).json({ error: 'このパスへのアクセスは許可されていません' });
    }

    // ファイルサイズチェック（1MB以上は拒否）
    let sizeStr;
    try {
      sizeStr = hostExec(`stat -c%s '${filePath}' 2>/dev/null`);
    } catch (e) {
      return res.status(404).json({ error: 'ファイルが見つかりません' });
    }
    const size = parseInt(sizeStr);
    if (size > 1048576) {
      return res.json({ content: null, error: 'ファイルが大きすぎます（1MB超）', size });
    }

    // バイナリチェック
    let isBinary = false;
    try {
      const fileType = hostExec(`file --mime-type -b '${filePath}'`);
      isBinary = !fileType.startsWith('text/') && !fileType.includes('json') && !fileType.includes('xml') && !fileType.includes('javascript');
    } catch (e) {}

    if (isBinary) {
      return res.json({ content: null, error: 'バイナリファイルのため表示できません', size });
    }

    const content = hostExec(`cat '${filePath}'`);
    res.json({ content, size, path: filePath });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: サーバー監視 =====
app.get('/api/system', (req, res) => {
  try {
    // CPU使用率
    let cpuUsage = 0;
    try {
      const cpuLine = hostExec("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'");
      cpuUsage = parseFloat(cpuLine) || 0;
    } catch (e) {}

    // メモリ
    let memTotal = 0, memUsed = 0, memPercent = 0;
    try {
      const memInfo = hostExec("free -b | grep Mem");
      const parts = memInfo.split(/\s+/);
      memTotal = parseInt(parts[1]) || 0;
      memUsed = parseInt(parts[2]) || 0;
      memPercent = memTotal > 0 ? Math.round((memUsed / memTotal) * 100) : 0;
    } catch (e) {}

    // ディスク
    let diskTotal = 0, diskUsed = 0, diskPercent = 0;
    try {
      const diskInfo = hostExec("df -B1 / | tail -1");
      const parts = diskInfo.split(/\s+/);
      diskTotal = parseInt(parts[1]) || 0;
      diskUsed = parseInt(parts[2]) || 0;
      diskPercent = parseInt(parts[4]) || 0;
    } catch (e) {}

    // 稼働時間
    let uptime = '';
    try { uptime = hostExec("uptime -p"); } catch (e) {}

    // ロードアベレージ
    let loadAvg = '';
    try { loadAvg = hostExec("cat /proc/loadavg | awk '{print $1, $2, $3}'"); } catch (e) {}

    res.json({
      cpu: { percent: cpuUsage },
      memory: { total: memTotal, used: memUsed, percent: memPercent },
      disk: { total: diskTotal, used: diskUsed, percent: diskPercent },
      uptime,
      loadAvg,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: Dockerコンテナ管理 =====
app.get('/api/containers', (req, res) => {
  try {
    let raw;
    try {
      raw = hostExec("docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}\\t{{.Ports}}\\t{{.Image}}\\t{{.CreatedAt}}'");
    } catch (e) {
      return res.json([]);
    }
    const containers = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      const [id, name, status, ports, image, created] = line.split('\t');
      const isRunning = status.startsWith('Up');
      containers.push({ id: id.substring(0, 12), name, status, ports, image, created, isRunning });
    }
    res.json(containers);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/containers/:name/restart', (req, res) => {
  try {
    const { name } = req.params;
    // admin_panel自身の再起動は禁止
    if (name === 'admin_panel') {
      return res.status(400).json({ error: '管理パネル自身は再起動できません' });
    }
    hostExec(`docker restart ${name}`);
    res.json({ success: true, message: `${name} を再起動しました` });
  } catch (e) {
    res.status(500).json({ error: `再起動失敗: ${e.message}` });
  }
});

app.post('/api/containers/:name/stop', (req, res) => {
  try {
    const { name } = req.params;
    if (name === 'admin_panel') {
      return res.status(400).json({ error: '管理パネル自身は停止できません' });
    }
    hostExec(`docker stop ${name}`);
    res.json({ success: true, message: `${name} を停止しました` });
  } catch (e) {
    res.status(500).json({ error: `停止失敗: ${e.message}` });
  }
});

app.post('/api/containers/:name/start', (req, res) => {
  try {
    const { name } = req.params;
    hostExec(`docker start ${name}`);
    res.json({ success: true, message: `${name} を起動しました` });
  } catch (e) {
    res.status(500).json({ error: `起動失敗: ${e.message}` });
  }
});

app.get('/api/containers/:name/logs', (req, res) => {
  try {
    const { name } = req.params;
    const lines = req.query.lines || 50;
    const logs = hostExec(`docker logs --tail ${lines} ${name} 2>&1`);
    res.json({ name, logs });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== API: ワンクリックデプロイ =====
app.post('/api/deploy/:app', (req, res) => {
  try {
    const { app: appName } = req.params;
    const allowed = ['sandbox', 'app1', 'app2'];
    if (!allowed.includes(appName)) {
      return res.status(400).json({ error: `${appName} はデプロイ対象ではありません（${allowed.join(', ')} のみ）` });
    }
    const dir = `/var/www/app/${appName}`;
    const output = hostExec(`cd ${dir} && docker compose down --remove-orphans 2>&1 && docker compose up -d --build 2>&1`);
    res.json({ success: true, message: `${appName} のデプロイが完了しました`, output });
  } catch (e) {
    res.status(500).json({ error: `デプロイ失敗: ${e.message}` });
  }
});

// ===== API: アプリ死活監視 =====
app.get('/api/health', (req, res) => {
  try {
    const apps = [
      { name: 'sandbox', url: 'http://127.0.0.1:3001/', path: '/sandbox/' },
      { name: 'app1', url: 'http://127.0.0.1:3002/', path: '/app1/' },
      { name: 'app2', url: 'http://127.0.0.1:3003/', path: '/app2/' },
      { name: 'admin', url: 'http://127.0.0.1:3004/', path: '/admin/' },
      { name: 'gitea', url: 'http://127.0.0.1:3000/', path: '(git.haregake-lab.com)' },
    ];

    const results = [];
    for (const app of apps) {
      let status = 'down';
      let httpCode = 0;
      let responseTime = 0;
      try {
        const startMs = Date.now();
        const curlOut = hostExec(`curl -so /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 ${app.url} 2>/dev/null`);
        responseTime = Date.now() - startMs;
        httpCode = parseInt(curlOut) || 0;
        if (httpCode >= 200 && httpCode < 500) status = 'up';
      } catch (e) {
        status = 'down';
      }
      results.push({ ...app, status, httpCode, responseTime });
    }
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== フロントエンド =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(3000, '0.0.0.0', () => {
  console.log('管理パネル起動: ポート3000');
});
