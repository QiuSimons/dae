const canvas = document.getElementById("trafficChart");
const ctx = canvas.getContext("2d");

const chartState = {
  upload: [1.4, 1.8, 1.6, 2.2, 2.8, 3.1, 4.5, 3.7, 5.4, 6.8, 9.4, 12.2, 8.9, 7.3, 11.5, 10.1, 12.8, 8.4, 6.6, 9.3],
  download: [-0.12, -0.2, -0.16, -0.3, -0.42, -0.36, -0.51, -0.62, -0.58, -0.72, -0.86, -1.12, -0.98, -0.88, -1.26, -1.08, -0.94, -0.78, -0.7, -0.82],
};

function randomRange(min, max) {
  return Math.random() * (max - min) + min;
}

function mapToY(value, height) {
  const max = 14.7;
  const min = -2.2;
  return ((max - value) / (max - min)) * height;
}

function createSmoothPath(points, width, height) {
  const step = width / (points.length - 1);
  const mapped = points.map((value, index) => ({
    x: index * step,
    y: mapToY(value, height),
  }));

  return mapped;
}

function drawGrid(width, height) {
  ctx.strokeStyle = "rgba(122, 132, 142, 0.12)";
  ctx.lineWidth = 1;

  for (let i = 0; i < 5; i += 1) {
    const y = (height / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  for (let i = 0; i < 6; i += 1) {
    const x = (width / 5) * i;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
}

function drawSeries(points, width, height, options) {
  const { stroke, fill } = options;
  const mapped = createSmoothPath(points, width, height);

  ctx.beginPath();
  ctx.moveTo(mapped[0].x, mapped[0].y);

  for (let i = 0; i < mapped.length - 1; i += 1) {
    const current = mapped[i];
    const next = mapped[i + 1];
    const cpX = (current.x + next.x) / 2;
    ctx.bezierCurveTo(cpX, current.y, cpX, next.y, next.x, next.y);
  }

  ctx.lineWidth = 3;
  ctx.strokeStyle = stroke;
  ctx.stroke();

  ctx.lineTo(width, height);
  ctx.lineTo(0, height);
  ctx.closePath();

  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, fill);
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = gradient;
  ctx.fill();
}

function renderChart() {
  const ratio = window.devicePixelRatio || 1;
  const bounds = canvas.getBoundingClientRect();
  canvas.width = Math.floor(bounds.width * ratio);
  canvas.height = Math.floor(bounds.height * ratio);
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(ratio, ratio);

  const width = bounds.width;
  const height = bounds.height;
  ctx.clearRect(0, 0, width, height);
  drawGrid(width, height);

  drawSeries(chartState.upload, width, height, {
    stroke: "#4cc0b5",
    fill: "rgba(76, 192, 181, 0.24)",
  });

  drawSeries(chartState.download, width, height, {
    stroke: "#9b84d7",
    fill: "rgba(155, 132, 215, 0.18)",
  });
}

function shiftSeries() {
  const lastUp = chartState.upload[chartState.upload.length - 1];
  const lastDown = chartState.download[chartState.download.length - 1];

  const nextUp = Math.max(1.2, Math.min(13.8, lastUp + randomRange(-2.2, 2.2)));
  const nextDown = Math.max(-1.5, Math.min(-0.05, lastDown + randomRange(-0.24, 0.24)));

  chartState.upload.shift();
  chartState.download.shift();
  chartState.upload.push(Number(nextUp.toFixed(2)));
  chartState.download.push(Number(nextDown.toFixed(2)));

  document.getElementById("uploadRate").textContent = randomRange(1.6, 3.4).toFixed(1);
  document.getElementById("downloadRate").textContent = randomRange(11.5, 16.8).toFixed(1);

  const cpu = Math.round(randomRange(58, 82));
  const memory = Math.round(randomRange(46, 71));
  const core = Math.round(randomRange(8, 26));

  document.getElementById("cpuValue").textContent = `${cpu}%`;
  document.getElementById("memoryValue").textContent = `${memory}%`;
  document.getElementById("coreValue").textContent = `${core}%`;

  document.querySelector(".meter-fill.cpu").style.width = `${cpu}%`;
  document.querySelector(".meter-fill.memory").style.width = `${memory}%`;
  document.querySelector(".meter-fill.core").style.width = `${core}%`;

  const active = Math.round(randomRange(140, 182));
  const tcp = Math.round(active * randomRange(0.64, 0.78));
  const udp = active - tcp;

  document.getElementById("activeConnections").textContent = String(active);
  document.getElementById("tcpConnections").textContent = String(tcp);
  document.getElementById("udpConnections").textContent = String(udp);

  renderChart();
}

function setupProxyTabs() {
  const tabs = document.querySelectorAll(".proxy-tab");
  const cards = document.querySelectorAll(".proxy-card");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");

      const group = tab.dataset.group;
      cards.forEach((card) => {
        const groups = (card.dataset.groups || "").split(" ");
        const shouldShow = group === "all" || groups.includes(group);
        card.classList.toggle("hidden", !shouldShow);
      });
    });
  });
}

window.addEventListener("resize", renderChart);
setupProxyTabs();
renderChart();
window.setInterval(shiftSeries, 1800);
