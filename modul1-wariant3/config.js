module.exports = {
  // Google reCAPTCHA v2 („Nie jestem robotem”) przy zmianie hasła.
  // Domyślnie są tu oficjalne klucze testowe Google: weryfikacja zawsze przechodzi, a widżet
  // pokazuje napis o trybie testowym. Własne klucze: Google Cloud Console > Security > reCAPTCHA.
  recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
  recaptchaSecret: process.env.RECAPTCHA_SECRET || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',

  // Canarytokens (https://canarytokens.org): adres tokenu typu „Web bug / URL token”.
  // Serwer wywołuje go przy każdej próbie logowania na konto-pułapkę, a Canarytokens wysyła e-mail.
  canaryAccountUrl: process.env.CANARY_ACCOUNT_URL || 'http://canarytokens.com/feedback/images/li6qxv7bix5iiorl5d89jxr4d/post.jsp',

  // Konta-pułapki (honeytoken). Nie istnieją w bazie i nikt uprawniony z nich nie korzysta.
  decoyLogins: ['administrator'],
};
