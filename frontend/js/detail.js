document.addEventListener("DOMContentLoaded", function () {
  fetch("http://localhost:8000/prediction", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  })
    .then((res) => res.json())
    .then((data) => {
    const report = data?.predicted_probability;
    const score = report?.SCORE;
    const $result = $("#result");
    const $table = $("#resultTable").removeClass().addClass("table table-striped");

    const displayResult = (text, color, tableClass) => {
      $("#result, #report").show();
      $("#detailsLink").removeClass("disabled");
      $result.text(text).css("color", color).show();
      $table.addClass(tableClass).show();
      };

    if (typeof score !== "number") {
      console.error("SCORE is missing or invalid.");
      return;
    }

    if (score >= 70) {
      displayResult("Safe! 🔐", "#43d841", "table-success");
    } else if (score >= 50) {
      displayResult("Suspicious! ⚠️", "#d8c441", "table-warning");
    } else {
      displayResult("Phishing! 🚨", "#D83F3F", "table-danger");
    }

      const setField = (
        id,
        value,
        yesText,
        noText,
        yesColor = "",
        noColor = "red"
      ) => {
        const display = value ? yesText ?? value : noText ?? "None";
        const color = value ? yesColor : noColor;
        $(`#${id}`).html(`<span style="color: ${color};">${display}</span>`);
      };
      setField("NameServers", report.whois?.["Name Servers"]);
      setField("location", report.location);
      setField("model", `${report.probability}%`);
      setField("has_url", report.URL);
      setField("has_domain", report.finalDomain);
      setField("has_ip", report.ipAddress);
      setField("sll_cert", report.isSslCertified, "Certified", "Not Certified", "green");
      setField("dns_blacklist", report.isntBlacklisted, "Not Blacklisted", "Blacklisted", "green");
      setField("age", report.age);
      setField("Temp_Domain", report.isntSusDomain);
      setField("Google_WebSafe", report.isGoogleSafePassed, "Safe", "Unsafe", "green");
      setField("similarity_score", `${report.isLegit?.["domain"]} (${report.isLegit?.["score"]}%)`);
    })
    .catch((err) => {
      console.error("Request failed:", err);
      alert("Network Error Occurred! Please try again.");
    });

  fetch("header.html")
    .then((res) => res.text())
    .then((html) => (document.getElementById("top-header").innerHTML = html));
});
