import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMacrosession } from "../controllers/useMacrosession";
import { SubnetTopologyMap } from "../components/SubnetTopologyMap";
import { SessionTrackingView } from "../components/SessionTrackingView";
import { SessionReportView } from "../components/SessionReportView";
import type { SubnetScanNode } from "../types/subnetScan";

type EmbeddedTab = "tracking" | "report";

export function MacrosessionTopologyPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [embeddedTab, setEmbeddedTab] = useState<EmbeddedTab>("report");
  const { macrosession, isLoading } = useMacrosession(sessionId ?? "");

  if (isLoading) return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Loading...</p>;
  if (!macrosession) return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Macrosession not found.</p>;

  const nodes: SubnetScanNode[] = macrosession.children.map((child) => ({
    id: child.id,
    ip: child.discoveryMetadata?.ip ?? child.target,
    name: child.target,
    deviceType: child.deviceType ?? "unknown",
    hostStatus: child.hostStatus ?? "pending",
  }));

  function selectHost(hostId: string) {
    setSelectedHostId(hostId);
    setEmbeddedTab("report");
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 16 }}>
      <div style={{ flex: "0 0 55%", minHeight: 320 }}>
        <SubnetTopologyMap
          cidr={macrosession.target}
          nodes={nodes}
          selectedHostId={selectedHostId}
          onSelectHost={selectHost}
        />
      </div>
      <div style={{ flex: 1, overflowY: "auto", borderTop: "1px solid var(--ares-border)", paddingTop: 16 }}>
        {selectedHostId ? (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 20, maxWidth: 400 }}>
              {(["tracking", "report"] as const).map((tab) => {
                const isActive = embeddedTab === tab;
                return (
                  <button
                    key={tab}
                    onClick={() => setEmbeddedTab(tab)}
                    style={{
                      textAlign: "left", padding: "10px 14px", cursor: "pointer",
                      border: `1px solid ${isActive ? "var(--ares-blue-border)" : "var(--ares-border)"}`,
                      background: isActive ? "var(--ares-blue-dim)" : "var(--ares-surface)",
                      borderRadius: 8,
                    }}
                  >
                    <p style={{
                      margin: 0, fontSize: 13, fontWeight: 500,
                      color: isActive ? "var(--ares-blue-text)" : "var(--ares-text)",
                    }}>
                      {tab === "tracking" ? "Agent tracking" : "Report"}
                    </p>
                  </button>
                );
              })}
            </div>
            {embeddedTab === "tracking" ? (
              <SessionTrackingView sessionId={selectedHostId} />
            ) : (
              <SessionReportView sessionId={selectedHostId} />
            )}
          </>
        ) : (
          <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Select a device from the map</p>
        )}
      </div>
    </div>
  );
}
