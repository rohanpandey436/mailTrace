var MT = MT || {};

(function (MT) {
  function sharedProvider(input) {
    var host = MT.py.rstrip(MT.py.strip(input || "").toLowerCase(), ".");
    if (!host) return "";
    var providers = MT.K("knowledge").SHARED_MAIL_PROVIDERS;
    var found = "";
    providers.forEach(function (provider, domain) {
      if (found) return;
      if (host === domain || host.endsWith("." + domain)) found = provider;
    });
    return found;
  }

  MT.knowledge = {
    sharedProvider: sharedProvider,
  };
})(MT);
