// Twitter developでOAuth2の登録をした際のクライアントidとシークレットキー
// APP_IDとAPP_SECRETではないので注意
const CLIENT_ID = ""
const CLIENT_SECRET = ""

// Twwetのスコープ、読み取りのみにしている
const SCOPE = "tweet.read users.read offline.access"
const AUTH_URL = "https://twitter.com/i/oauth2/authorize"
const TOKEN_URL = "https://api.twitter.com/2/oauth2/token"

const USER_URL = "https://api.twitter.com/2/users"

function getService() {
  pkceChallengeVerifier();

  const prop = PropertiesService.getUserProperties();

  // OAuth2認証情報を作成
  return OAuth2.createService("twitter")
    .setAuthorizationBaseUrl(AUTH_URL)
    .setTokenUrl(TOKEN_URL + '?code_verifier=' + prop.getProperty("code_verifier"))
    .setClientId(CLIENT_ID)
    .setClientSecret(CLIENT_SECRET)
    .setScope(SCOPE)
    .setCallbackFunction("authCallback")　//認証を受けたら受け取る関数を指定する
    .setPropertyStore(PropertiesService.getScriptProperties())  //スクリプトプロパティに保存する
    .setParam("response_type", "code")
    .setParam('code_challenge_method', 'S256')
    .setParam('code_challenge', prop.getProperty("code_challenge"))
    .setTokenHeaders({
      'Authorization': 'Basic ' + Utilities.base64Encode(APP_ID + ':' + APP_SECRET),
      'Content-Type': 'application/x-www-form-urlencoded'
    })
}

function authCallback(request) {
  // 認証情報の取得
  const service = getService();
  // https://script.google.com/macros/d/スクリプトID/usercallback
  // 上記にリダイレクトする際の表示を作成
  // デプロイidではなくスクリプトidなので注意(なのでデプロイの必要はない)
  const authorized = service.handleCallback(request);
  if (authorized) {
    return HtmlService.createHtmlOutput('Success!');
  } else {
    return HtmlService.createHtmlOutput('Denied.');
  }
}

function pkceChallengeVerifier() {
  const userProps = PropertiesService.getUserProperties();
  if (!userProps.getProperty("code_verifier")) {
    let verifier = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    for (let i = 0; i < 128; i++) {
      verifier += possible.charAt(Math.floor(Math.random() * possible.length));
    }

    const sha256Hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, verifier)

    console.log(sha256Hash)

    const challenge = Utilities.base64Encode(sha256Hash)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    userProps.setProperty("code_verifier", verifier)
    userProps.setProperty("code_challenge", challenge)
  }
}

function logRedirectUri() {
  const service = getService();
  Logger.log(service.getRedirectUri());
}

// 初回はここの関数を実行
function mainAuth() {
  // 認証情報を取得
  const service = getService();
  if (service.hasAccess()) {
    // すでに認証済み
    Logger.log("Already authorized");
  } else {
    const authorizationUrl = service.getAuthorizationUrl();
    // 表示されたURLに遷移することで認証画面に移る
    // リダイレクトURLがパーセントエンコーディングされているのでデコードを施す。
    Logger.log('Open the following URL and re-run the script: %s', decodeURIComponent(authorizationUrl));
  }
}
