document.addEventListener("DOMContentLoaded", function () {
  const urlInput = document.getElementById("urlInput");
  const requirementList = document.querySelectorAll(".requirement-list li");
  const sendButton = document.getElementById("sendButton");

const requirements = [
  // Requirement 1: Must start with http://, https://, or ftp://
  { 
    regex: /^(https?:\/\/|ftp:\/\/)/i, 
    index: 0 
  },

  // Requirement 2: Full URL structure validation
  {
    test: (url) => {
      const pattern = new RegExp(
        "^(https?:\\/\\/|ftp:\\/\\/)" +                  // Protocol
        "((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+" +       // Subdomains + Domain
        "[a-z]{2,})" +                                   // Top-level domain
        "(\\:\\d{1,5})?" +                               // Optional port
        "(\\/[-a-z\\d%@_.~+&:]*)*" +                     // Path
        "(\\?[;&a-z\\d%@_.,~+=-]*)?" +                   // Query string
        "(\\#[-a-z\\d_]*)?$",                            // Fragment
        "i"
      );
      return pattern.test(url) && url.length >= 5 && url.length <= 200;
    },
    index: 1,
  },
];

  urlInput.addEventListener("keyup", (e) => {
    const value = e.target.value;
    let allValid = true;

    requirements.forEach((req) => {
      const isValid = req.regex ? req.regex.test(value) : req.test(value);
      const item = requirementList[req.index];

      item.classList.toggle("valid", isValid);
      item.classList.toggle("invalid", !isValid);

      const icon = item.querySelector("i");
      if (icon) {
        icon.className = isValid ? "fa-solid fa-check" : "fa-solid fa-circle";
      }

      if (!isValid) allValid = false;
    });

    sendButton.disabled = !allValid;
  });
});

$(".messageBox").submit(function (e) {
  e.preventDefault();

  const url = $("#urlInput").val();
  const $container = $(".text-container");
  const $loader = $(".ui-loader");
  const $result = $("#result");
  const $description = $("#description");
  const $subtext = $("#subtext");

  const displayResult = (text, code, desc, color) => {
    $loader.hide();
    $(
      "section .messageBox, section .validator, section .main-text, section .heading-text, section .subtext"
    ).hide();
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
            "It might be a phishing scam.",
            "#d8c441"
          );
        } else {
          displayResult(
            "Phishing! 🚨",
            "This website is dangerous.",
            "It may steal your data. Avoid entering personal info.",
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
