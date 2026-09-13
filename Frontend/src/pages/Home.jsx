import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

function Home() {
  const [isScanning, setIsScanning] = useState(false);
  const [recentScans, setRecentScans] = useState([]);
  const [stats, setStats] = useState(null);

  // Settings
  const [showSettings, setShowSettings] = useState(false);
  const [apiIp, setApiIp] = useState(
    localStorage.getItem("apiIp") || "127.0.0.1"
  );
  const [tempIp, setTempIp] = useState(
    localStorage.getItem("apiIp") || "127.0.0.1"
  );

  const API_BASE = `http://${apiIp}:8000`;

  const saveSettings = () => {
    const cleanedIp = tempIp.trim();

    if (!cleanedIp) {
      return;
    }

    localStorage.setItem("apiIp", cleanedIp);
    setApiIp(cleanedIp);
    setShowSettings(false);
  };

  useEffect(() => {
    const fetchScans = () => {
      fetch(`${API_BASE}/recent-scans`)
        .then((response) => response.json())
        .then((data) => {
          setRecentScans(data.scans);
        })
        .catch((error) => {
          console.error("Failed to fetch recent scans:", error);
        });
    };

    const fetchStats = () => {
      fetch(`${API_BASE}/statistics`)
        .then((response) => response.json())
        .then((data) => {
          setStats(data);
        })
        .catch((error) => {
          console.error("Failed to fetch statistics:", error);
        });
    };

    fetchScans();
    fetchStats();

    const interval = setInterval(() => {
      fetchScans();
      fetchStats();
    }, 2000);

    return () => clearInterval(interval);
  }, [API_BASE]);

  useEffect(() => {
    const checkStatus = () => {
      fetch(`${API_BASE}/scan-status`)
        .then((response) => response.json())
        .then((data) => {
          setIsScanning(data.running);
        })
        .catch((error) => {
          console.error("Failed to fetch scan status:", error);
        });
    };

    checkStatus();

    const interval = setInterval(checkStatus, 2000);

    return () => clearInterval(interval);
  }, [API_BASE]);

  const scan = recentScans.length > 0 ? recentScans[0] : null;

  const recentThreats = recentScans.filter(
    (scan) => scan.prediction !== "BENIGN"
  );

  const getProtocolName = (protocol) => {
    if (protocol === 6) return "TCP";
    if (protocol === 17) return "UDP";

    return protocol;
  };

  const handleScanToggle = async () => {
    const endpoint = isScanning
      ? `${API_BASE}/stop-scan`
      : `${API_BASE}/start-scan`;

    try {
      const response = await fetch(endpoint, {
        method: "POST",
      });

      const data = await response.json();

      if (
        data.status === "started" ||
        data.status === "already_running"
      ) {
        setIsScanning(true);
      }

      if (
        data.status === "stopped" ||
        data.status === "not_running"
      ) {
        setIsScanning(false);
      }
    } catch (error) {
      console.error("Failed to control scan:", error);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100">

      {/* Header */}
      <header className="border-b bg-white px-8 py-5">
        <div className="mx-auto flex max-w-7xl items-center justify-between">

          <div>
            <h1 className="text-2xl font-bold text-slate-900">
              KAVACH AI
            </h1>

            <p className="text-sm text-slate-500">
              AI-Based Cyber Threat Detection
            </p>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 border-r pr-6 px-4 py-2 text-sm font-medium text-slate-600">
              Current ip: {apiIp}:8000
            </div>
            <div className="flex items-center gap-2 border-r pr-6">
              <span
                className={`h-3 w-3 rounded-full ${
                  isScanning
                    ? "animate-pulse bg-green-500"
                    : "bg-slate-400"
                }`}
              />

              <span className="text-sm font-medium text-slate-700">
                {isScanning
                  ? "LIVE MONITORING"
                  : "MONITORING OFF"}
              </span>
            </div>

            <nav className="flex items-center gap-2">
              <Link
                to="/"
                className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white"
              >
                Live Monitoring
              </Link>

              <Link
                to="/stats"
                className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100"
              >
                Statistics
              </Link>

              {/* Settings Button */}
              <button
                onClick={() => {
                  setTempIp(apiIp);
                  setShowSettings(true);
                }}
                className="flex h-10 w-10 items-center justify-center rounded-lg text-xl text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                title="Settings"
              >
                ⚙
              </button>
            </nav>

          </div>
        </div>
      </header>

      {/* Settings Overlay */}
      {showSettings && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/20 pt-24"
          onClick={() => setShowSettings(false)}
        >
          <div
            className="w-full max-w-sm rounded-xl bg-white p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >

            <div className="flex items-center justify-between">

              <div>
                <h2 className="text-lg font-semibold text-slate-900">
                  Settings
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Configure backend connection
                </p>
              </div>

              <button
                onClick={() => setShowSettings(false)}
                className="text-xl text-slate-400 transition hover:text-slate-700"
              >
                ×
              </button>

            </div>

            <div className="mt-6">

              <label className="text-sm font-medium text-slate-700">
                Backend IP Address
              </label>

              <input
                type="text"
                value={tempIp}
                onChange={(event) => setTempIp(event.target.value)}
                placeholder="127.0.0.1"
                className="mt-2 w-full rounded-lg border border-slate-300 px-4 py-2.5 font-mono text-sm outline-none transition focus:border-slate-500 focus:ring-2 focus:ring-slate-200"
              />

              <p className="mt-2 text-xs text-slate-400">
                Example: 192.168.1.105
              </p>

            </div>

            <button
              onClick={saveSettings}
              className="mt-6 w-full rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800"
            >
              Save Settings
            </button>

            <p className="mt-4 text-center text-xs text-slate-400">
              Tap outside to go back
            </p>

          </div>
        </div>
      )}

      <main className="mx-auto max-w-7xl space-y-6 p-6">

        {/* Dashboard Summary */}
        {stats && (
          <section className="grid gap-5 md:grid-cols-2 lg:grid-cols-4">

            <StatCard
              title="Total Flows"
              value={stats.total_flows}
              icon="↗"
              color="text-slate-700"
              background="bg-slate-50"
            />

            <StatCard
              title="Benign Flows"
              value={stats.benign}
              icon="✓"
              color="text-green-600"
              background="bg-green-50"
            />

            <StatCard
              title="DDoS Attacks"
              value={stats.ddos}
              icon="!"
              color="text-red-600"
              background="bg-red-50"
            />

            <StatCard
              title="PortScan Attacks"
              value={stats.portscan}
              icon="⚠"
              color="text-orange-600"
              background="bg-orange-50"
            />

          </section>
        )}

        {/* Live Detection */}
        <section className="rounded-xl bg-slate-900 p-6 text-white shadow-sm">

          <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">

            <div>
              <div className="flex items-center gap-3">

                <span
                  className={`h-3 w-3 rounded-full ${
                    isScanning
                      ? "animate-pulse bg-green-400"
                      : "bg-slate-500"
                  }`}
                />

                <h2 className="text-xl font-semibold">
                  Live Detection
                </h2>

              </div>

              <p className="mt-2 text-sm text-slate-400">
                Continuously monitor incoming network traffic
              </p>
            </div>

            <button
              onClick={handleScanToggle}
              className={`rounded-lg px-5 py-2.5 text-sm font-semibold transition ${
                isScanning
                  ? "bg-red-500 hover:bg-red-600"
                  : "bg-green-500 hover:bg-green-600"
              }`}
            >
              {isScanning ? "Stop Scan" : "Start Scan"}
            </button>

          </div>

          {isScanning && (
            <div className="mt-5 rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-3 text-sm text-green-400">

              <div className="flex items-center gap-2">

                <span className="h-2 w-2 animate-pulse rounded-full bg-green-400" />

                <span>
                  Scanning incoming network traffic...
                </span>

              </div>

            </div>
          )}

        </section>

        {/* Live Detection Table */}
        <section className="rounded-xl bg-white p-6 shadow-sm">

          <div className="mb-5 flex items-center justify-between">

            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                Live Detection Table
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Recently processed network flows
              </p>
            </div>

            <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
              {recentScans.length} flows
            </span>

          </div>

          <div className="max-h-96 overflow-auto">

            <table className="w-full text-left text-sm">

              <thead className="sticky top-0 z-10 bg-slate-50">

                <tr className="border-b text-xs uppercase tracking-wide text-slate-500">

                  <th className="px-4 py-3 font-semibold">
                    Time
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Source IP
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Destination IP
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Protocol
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Packets
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Prediction
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Confidence
                  </th>

                </tr>

              </thead>

              <tbody>

                {recentScans.map((scan) => (

                  <tr
                    key={scan.id}
                    className="border-b last:border-0 transition hover:bg-slate-50"
                  >

                    <td className="whitespace-nowrap px-4 py-4 text-slate-600">
                      {new Date(
                        scan.timestamp
                      ).toLocaleTimeString()}
                    </td>

                    <td className="px-4 py-4 font-mono text-slate-700">
                      {scan.source_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4 font-mono text-slate-700">
                      {scan.destination_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4">

                      <span className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">
                        {getProtocolName(scan.protocol)}
                      </span>

                    </td>

                    <td className="px-4 py-4 text-slate-700">
                      {scan.packet_count}
                    </td>

                    <td className="px-4 py-4">
                      <PredictionBadge
                        prediction={scan.prediction}
                      />
                    </td>

                    <td className="px-4 py-4">

                      <div className="flex items-center gap-3">

                        <div className="h-2 w-20 overflow-hidden rounded-full bg-slate-200">

                          <div
                            className={`h-full rounded-full ${
                              scan.prediction === "BENIGN"
                                ? "bg-green-500"
                                : "bg-red-500"
                            }`}
                            style={{
                              width: `${
                                scan.prediction_score * 100
                              }%`,
                            }}
                          />

                        </div>

                        <span className="font-semibold text-slate-700">
                          {(
                            scan.prediction_score * 100
                          ).toFixed(1)}
                          %
                        </span>

                      </div>

                    </td>

                  </tr>

                ))}

                {recentScans.length === 0 && (

                  <tr>

                    <td
                      colSpan="7"
                      className="px-4 py-12 text-center"
                    >

                      <p className="font-medium text-slate-700">
                        No network flows detected yet
                      </p>

                      <p className="mt-1 text-sm text-slate-400">
                        Start monitoring to begin collecting traffic.
                      </p>

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        </section>

        {/* Recent Threats */}
        <section className="rounded-xl bg-white p-6 shadow-sm">

          <div className="mb-5">

            <div className="flex items-center gap-3">

              <h2 className="text-lg font-semibold text-slate-900">
                Recent Threats
              </h2>

              <span
                className={`rounded-full px-2.5 py-1 text-xs font-semibold ${
                  recentThreats.length > 0
                    ? "bg-red-100 text-red-700"
                    : "bg-green-100 text-green-700"
                }`}
              >
                {recentThreats.length} detected
              </span>

            </div>

            <p className="mt-1 text-sm text-slate-500">
              Recently detected malicious network activity
            </p>

          </div>

          <div className="overflow-x-auto">

            <table className="w-full text-left text-sm">

              <thead>

                <tr className="border-b bg-slate-50 text-xs uppercase tracking-wide text-slate-500">

                  <th className="px-4 py-3 font-semibold">
                    Time
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Source IP
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Destination IP
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Protocol
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Prediction
                  </th>

                  <th className="px-4 py-3 font-semibold">
                    Score
                  </th>

                </tr>

              </thead>

              <tbody>

                {recentThreats.map((threat) => (

                  <tr
                    key={threat.id}
                    className="border-b last:border-0 transition hover:bg-slate-50"
                  >

                    <td className="whitespace-nowrap px-4 py-4 text-slate-600">
                      {new Date(
                        threat.timestamp
                      ).toLocaleTimeString()}
                    </td>

                    <td className="px-4 py-4 font-mono text-slate-700">
                      {threat.source_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4 font-mono text-slate-700">
                      {threat.destination_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4">

                      <span className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">
                        {getProtocolName(threat.protocol)}
                      </span>

                    </td>

                    <td className="px-4 py-4">
                      <PredictionBadge
                        prediction={threat.prediction}
                      />
                    </td>

                    <td className="px-4 py-4 font-semibold text-slate-700">
                      {(
                        threat.prediction_score * 100
                      ).toFixed(1)}
                      %
                    </td>

                  </tr>

                ))}

                {recentThreats.length === 0 && (

                  <tr>

                    <td
                      colSpan="6"
                      className="px-4 py-12 text-center"
                    >

                      <div className="flex flex-col items-center">

                        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-50 text-xl text-green-600">
                          ✓
                        </div>

                        <p className="mt-3 font-medium text-slate-700">
                          No threats detected
                        </p>

                        <p className="mt-1 text-sm text-slate-400">
                          Network traffic is currently classified as safe.
                        </p>

                      </div>

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        </section>

        {/* Recent Scan Details */}
        {scan && (
          <section className="rounded-xl bg-white p-6 shadow-sm">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-900">
                Recent Scan Details
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Metadata from the latest network flow
              </p>

            </div>

            <div className="grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-3 lg:grid-cols-5">

              <Detail
                label="Timestamp"
                value={new Date(
                  scan.timestamp
                ).toLocaleString()}
              />

              <Detail
                label="Source IP"
                value={scan.source_ip || "N/A"}
              />

              <Detail
                label="Destination IP"
                value={scan.destination_ip || "N/A"}
              />

              <Detail
                label="Protocol"
                value={getProtocolName(scan.protocol)}
              />

              <Detail
                label="Source Port"
                value={scan.source_port}
              />

              <Detail
                label="Destination Port"
                value={scan.destination_port}
              />

              <Detail
                label="Packets"
                value={scan.packet_count}
              />

              <Detail
                label="Bytes"
                value={scan.total_bytes}
              />

              <Detail
                label="Duration"
                value={`${scan.duration} s`}
              />

            </div>

          </section>
        )}

        {!scan && (
          <section className="rounded-xl bg-white p-10 text-center shadow-sm">

            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-100 text-2xl text-slate-400">
              —
            </div>

            <p className="mt-4 font-medium text-slate-700">
              No scan data available yet
            </p>

            <p className="mt-1 text-sm text-slate-400">
              Start the live detector to generate network flow data.
            </p>

          </section>
        )}

        {/* Latest AI Prediction */}
        {scan && (
          <section className="rounded-xl bg-white p-6 shadow-sm">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-900">
                Latest AI Prediction
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Random Forest classification result
              </p>

            </div>

            <div className="grid gap-6 lg:grid-cols-2">

              <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">

                <div className="mb-5 flex items-center justify-between">

                  <h3 className="font-semibold text-slate-800">
                    Scan Metadata
                  </h3>

                  <span className="rounded-md bg-white px-2 py-1 text-xs font-medium text-slate-500 shadow-sm">
                    Latest Flow
                  </span>

                </div>

                <div className="space-y-3 text-sm">

                  <Info
                    label="Source IP"
                    value={scan.source_ip || "N/A"}
                  />

                  <Info
                    label="Destination IP"
                    value={scan.destination_ip || "N/A"}
                  />

                  <Info
                    label="Source Port"
                    value={scan.source_port}
                  />

                  <Info
                    label="Destination Port"
                    value={scan.destination_port}
                  />

                  <Info
                    label="Protocol"
                    value={getProtocolName(scan.protocol)}
                  />

                  <Info
                    label="Packets"
                    value={scan.packet_count}
                  />

                  <Info
                    label="Bytes"
                    value={scan.total_bytes}
                  />

                  <Info
                    label="Duration"
                    value={`${scan.duration} s`}
                  />

                </div>

              </div>

              <div className="flex flex-col items-center justify-center rounded-xl border border-slate-200 bg-slate-50 p-8">

                <p className="text-sm font-medium uppercase tracking-wide text-slate-500">
                  AI Prediction
                </p>

                <p
                  className={`mt-3 text-5xl font-bold ${
                    scan.prediction === "BENIGN"
                      ? "text-green-600"
                      : "text-red-600"
                  }`}
                >
                  {scan.prediction}
                </p>

                <div className="mt-6 w-full max-w-sm">

                  <div className="mb-2 flex items-center justify-between text-sm">

                    <span className="text-slate-500">
                      Prediction Confidence
                    </span>

                    <span className="font-semibold text-slate-800">
                      {(
                        scan.prediction_score * 100
                      ).toFixed(2)}
                      %
                    </span>

                  </div>

                  <div className="h-3 overflow-hidden rounded-full bg-slate-200">

                    <div
                      className={`h-full rounded-full transition-all ${
                        scan.prediction === "BENIGN"
                          ? "bg-green-500"
                          : "bg-red-500"
                      }`}
                      style={{
                        width: `${
                          scan.prediction_score * 100
                        }%`,
                      }}
                    />

                  </div>

                </div>

                <p className="mt-5 text-center text-xs text-slate-400">
                  Classification generated by the trained Random Forest model.
                </p>

              </div>

            </div>

          </section>
        )}

      </main>
    </div>
  );
}

function PredictionBadge({ prediction }) {
  const isBenign = prediction === "BENIGN";
  const isDDoS = prediction === "DDoS";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
        isBenign
          ? "bg-green-100 text-green-700"
          : isDDoS
          ? "bg-red-100 text-red-700"
          : "bg-orange-100 text-orange-700"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          isBenign
            ? "bg-green-500"
            : isDDoS
            ? "bg-red-500"
            : "bg-orange-500"
        }`}
      />

      {prediction}
    </span>
  );
}

function Detail({ label, value }) {
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
        {label}
      </p>

      <p className="mt-1 break-all font-semibold text-slate-800">
        {value}
      </p>
    </div>
  );
}

function Info({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-slate-200 pb-2">

      <span className="text-slate-500">
        {label}
      </span>

      <span className="break-all text-right font-mono font-medium text-slate-800">
        {value}
      </span>

    </div>
  );
}

function StatCard({
  title,
  value,
  icon,
  color,
  background,
}) {
  return (
    <div className="rounded-xl bg-white p-6 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md">

      <div className="flex items-start justify-between">

        <div>

          <p className="text-sm font-medium text-slate-500">
            {title}
          </p>

          <p
            className={`mt-2 text-3xl font-bold ${color}`}
          >
            {value}
          </p>

        </div>

        <div
          className={`flex h-10 w-10 items-center justify-center rounded-lg text-lg font-bold ${background} ${color}`}
        >
          {icon}
        </div>

      </div>

    </div>
  );
}

export default Home;