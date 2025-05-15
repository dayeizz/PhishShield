chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  if (!tabs.length) return console.error("No active tab found.");
  const url = tabs[0].url;
  console.log("Checking URL:", url);

  const $container = $(".text-container");
  const $loader = $(".ui-loader");
  const $result = $("#result");
  const $description = $("#description");
  const $subtext = $("#subtext");

  const displayResult = (text, code, desc, color) => {
    $loader.hide();
    $("section .main-text, section .heading-text, section .subtext").hide();
    $container.show();
    $result.text(text).css("color", color).show();
    $description.text(code).show();
    $subtext.text(desc).show();

};

  if (
    url.startsWith("chrome://") ||
    url.startsWith("https://www.google.com/search")
  ) {
    displayResult(
      "Hey! 🧐",
      "This page can't be scanned",
      "System or search pages aren't real websites. Try visiting an actual site to scan it.",
      "#ec0497"
    );
    return;
  }
  $loader.show();
  $result.add($description).add($subtext).hide();

  $.ajax({
    url: "http://localhost:8000/predict",
    method: "POST",
    dataType: "json",
    contentType: "application/json",
    data: JSON.stringify({ url }),
    success: function (response) {
      const msg = response?.message || "";
      const score = response?.predicted_probability?.SCORE;

      if (msg.includes("Forbidden")) {
        displayResult(
          "Shoot! ⛔",
          "403 - Forbidden",
          "Access to this resource on the server is denied.",
          "#D83F3F"
        );
      } else if (msg.includes("The URL is not valid or does not exist") || msg.includes("Bad request")) {
        displayResult(
          "Shoot! 🚩",
          "400 - Bad Request",
          "The server can't process the request due to invalid input.",
          "#FF8C00"
        );
      } else if (typeof score === "number") {
        $("#detailsLink").removeClass("disabled");

        if (score >= 70) {
          displayResult(
            "Safe! 🔐",
            "This website is safe to use.",
            "No signs of phishing detected. Always stay alert.",
            "#43d841"
          );
        } else if (score >= 50) {
          displayResult(
            "Suspicious! ⚠️",
            "This website looks suspicious.",
            "It might be a phishing scam. Remain vigilant against phishing.",
            "#d8c441"
          );
        } else {
          displayResult(
            "Phishing! 🚨",
            "This website is dangerous.",
            "It may steal your data. Avoid visiting this website.",
            "#D83F3F"
          );
        }
      } else {
        $loader.add($result).add($description).add($subtext).hide();
        console.error("SCORE is missing or undefined in the response.");
      }
    },
    error: function (_, textStatus, errorThrown) {
      displayResult(
        "Shoot! 🛠️",
        "500 - Internal Server Error",
        "We're working to fix the issue. Please try again later.",
        "#00CED1"
      );
      console.error("Request failed:", textStatus, errorThrown);
    },
  });
});

fetch("header.html")
  .then((res) => res.text())
  .then((html) => (document.getElementById("top-header").innerHTML = html));
