const API_BASE = "https://suspicious-login-detector-production.up.railway.app";

const logInput = document.getElementById("logInput");
const thresholdInput = document.getElementById("threshold");
const fileInput = document.getElementById("fileInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const resultDiv = document.getElementById("result");
const summaryP = document.getElementById("summary");
const ipTableBody = document.querySelector("#ipTable tbody");
const userTableBody = document.querySelector("#userTable tbody");
const errorDiv = document.getElementById("error");

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
        logInput.value = e.target.result;
    };
    reader.readAsText(file);
});

analyzeBtn.addEventListener("click", async () => {
    const csvContent = logInput.value.trim();
    const threshold = parseInt(thresholdInput.value, 10) || 5;

    errorDiv.classList.add("hidden");
    resultDiv.classList.add("hidden");
    errorDiv.textContent = "";
    summaryP.textContent = "";
    ipTableBody.innerHTML = "";
    userTableBody.innerHTML = "";

    if (!csvContent) {
        errorDiv.textContent = "Please paste or upload a CSV log file.";
        errorDiv.classList.remove("hidden");
        return;
    }

    try {
        const res = await fetch(
            `${API_BASE}/api/analyze?threshold=${encodeURIComponent(threshold)}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "text/plain"
                },
                body: csvContent
            }
        );

        if (!res.ok) {
            throw new Error("Server error: " + res.status);
        }

        const data = await res.json();
        renderResult(data, threshold);
    } catch (e) {
        errorDiv.textContent = "Error analyzing logs: " + e.message;
        errorDiv.classList.remove("hidden");
    }
});

function renderResult(data, threshold) {
    summaryP.textContent =
        `Total log entries: ${data.totalEntries} | Unique IPs: ${data.uniqueIps} | Threshold: ${threshold}`;

    if (data.suspiciousIps && data.suspiciousIps.length > 0) {
        data.suspiciousIps.forEach(ip => {
            const tr = document.createElement("tr");
            const tdIp = document.createElement("td");
            const tdCount = document.createElement("td");
            tdIp.textContent = ip.ip;
            tdCount.textContent = ip.failedCount;
            tr.appendChild(tdIp);
            tr.appendChild(tdCount);
            ipTableBody.appendChild(tr);
        });
    } else {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 2;
        td.textContent = "No suspicious IPs found.";
        tr.appendChild(td);
        ipTableBody.appendChild(tr);
    }

    if (data.attackedUsers && data.attackedUsers.length > 0) {
        data.attackedUsers.forEach(user => {
            const tr = document.createElement("tr");
            const tdUser = document.createElement("td");
            const tdCount = document.createElement("td");
            tdUser.textContent = user.username;
            tdCount.textContent = user.failedCount;
            tr.appendChild(tdUser);
            tr.appendChild(tdCount);
            userTableBody.appendChild(tr);
        });
    } else {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 2;
        td.textContent = "No usernames under attack.";
        tr.appendChild(td);
        userTableBody.appendChild(tr);
    }

    resultDiv.classList.remove("hidden");
}
