import type { CSSProperties } from "react";
import type { HostStatus } from "../types/session";
import type { SubnetScanNode } from "../types/subnetScan";
import { useZoomPan } from "../controllers/useZoomPan";

interface SubnetTopologyMapProps {
  cidr: string;
  nodes: SubnetScanNode[];
  selectedHostId: string | null;
  onSelectHost: (hostId: string) => void;
}

const DEVICE_ICON: Record<string, string> = {
  chromecast: "📺",
  apple_tv: "📱",
  printer: "🖨",
  router: "📡",
  media_renderer: "🎞",
  generic_web_device: "🌐",
  unknown: "❓",
};

const STATUS_COLOR: Record<HostStatus, string> = {
  pending: "var(--ares-border-strong)",
  running: "var(--ares-blue)",
  complete: "var(--ares-green)",
  failed: "var(--ares-red)",
};

function statusLabel(status: HostStatus): string {
  if (status === "complete") return "Completed";
  if (status === "running") return "Running";
  if (status === "failed") return "Failed";
  return "Pending";
}

const NODE_SIZE = 64;
const RADIUS = 180;
const SVG_SIZE = 2 * (RADIUS + NODE_SIZE);

const btn: CSSProperties = {
  border: "1px solid var(--ares-border-strong)",
  background: "var(--ares-surface)",
  color: "var(--ares-text-muted)",
  cursor: "pointer",
  borderRadius: 6,
};

export function SubnetTopologyMap({ cidr, nodes, selectedHostId, onSelectHost }: SubnetTopologyMapProps) {
  const { scale, offset, zoomIn, zoomOut, reset, canZoomIn, canZoomOut, dragHandlers } = useZoomPan();
  const router = nodes.find((node) => node.deviceType === "router");
  const orbitNodes = router ? nodes.filter((node) => node.id !== router.id) : nodes;

  const positions = orbitNodes.map((node, index) => {
    const angle = (2 * Math.PI * index) / Math.max(orbitNodes.length, 1) - Math.PI / 2;
    return { node, x: RADIUS * Math.cos(angle), y: RADIUS * Math.sin(angle) };
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 4, marginBottom: 12 }}>
        <button onClick={zoomOut} disabled={!canZoomOut} aria-label="Zoom out"
          style={{ ...btn, width: 32, height: 32, fontSize: 18, opacity: canZoomOut ? 1 : 0.35 }}
        >&minus;</button>
        <button onClick={reset}
          style={{ ...btn, padding: "0 12px", height: 32, fontSize: 12 }}
        >{Math.round(scale * 100)}%</button>
        <button onClick={zoomIn} disabled={!canZoomIn} aria-label="Zoom in"
          style={{ ...btn, width: 32, height: 32, fontSize: 18, opacity: canZoomIn ? 1 : 0.35 }}
        >+</button>
      </div>

      <div
        style={{
          position: "relative", flex: 1, minHeight: 320,
          border: "1px solid var(--ares-border)", borderRadius: 8,
          background: "var(--ares-bg)", overflow: "hidden", cursor: "grab",
        }}
        {...dragHandlers}
      >
        <div
          style={{
            position: "absolute", top: "50%", left: "50%", width: 0, height: 0,
            transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`,
            transformOrigin: "center center",
          }}
        >
          <svg
            width={SVG_SIZE}
            height={SVG_SIZE}
            viewBox={`${-SVG_SIZE / 2} ${-SVG_SIZE / 2} ${SVG_SIZE} ${SVG_SIZE}`}
            style={{ position: "absolute", left: 0, top: 0, transform: "translate(-50%, -50%)", pointerEvents: "none" }}
          >
            {positions.map(({ node, x, y }) => (
              <line
                key={node.id}
                x1={0}
                y1={0}
                x2={x}
                y2={y}
                stroke={STATUS_COLOR[node.hostStatus]}
                strokeWidth={2}
                strokeOpacity={0.5}
              />
            ))}
          </svg>

          {router && (
            <TopologyNode
              node={router}
              isCenter
              isSelected={selectedHostId === router.id}
              onSelect={onSelectHost}
              style={{ transform: "translate(-50%, -50%)" }}
            />
          )}
          {!router && (
            <div
              style={{
                position: "absolute", transform: "translate(-50%, -50%)",
                width: NODE_SIZE, height: NODE_SIZE, borderRadius: "50%",
                border: "1px dashed var(--ares-border-strong)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 10, color: "var(--ares-text-dim)", textAlign: "center", padding: 4,
                fontFamily: "JetBrains Mono, monospace",
              }}
            >
              {cidr}
            </div>
          )}

          {positions.map(({ node, x, y }) => (
            <TopologyNode
              key={node.id}
              node={node}
              isSelected={selectedHostId === node.id}
              onSelect={onSelectHost}
              style={{ transform: `translate(calc(-50% + ${x}px), calc(-50% + ${y}px))` }}
            />
          ))}
        </div>
      </div>
      <p style={{ fontSize: 11, color: "var(--ares-text-dim)", marginTop: 6, fontFamily: "JetBrains Mono, monospace" }}>
        Drag to pan · Ctrl/Cmd + scroll to zoom
      </p>
    </div>
  );
}

interface TopologyNodeProps {
  node: SubnetScanNode;
  isSelected: boolean;
  isCenter?: boolean;
  onSelect: (hostId: string) => void;
  style: CSSProperties;
}

function TopologyNode({ node, isSelected, isCenter, onSelect, style }: TopologyNodeProps) {
  return (
    <button
      onClick={() => onSelect(node.id)}
      onMouseDown={(e) => e.stopPropagation()}
      title={`${node.name} · ${statusLabel(node.hostStatus)}`}
      style={{
        position: "absolute", ...style,
        display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
        border: "none", background: "transparent", cursor: "pointer", padding: 0,
      }}
    >
      <div
        style={{
          width: NODE_SIZE, height: NODE_SIZE, borderRadius: "50%",
          background: STATUS_COLOR[node.hostStatus],
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: isCenter ? 26 : 22,
          border: isSelected ? "3px solid var(--ares-text)" : "3px solid transparent",
          boxShadow: isSelected ? "0 0 0 2px var(--ares-surface)" : "none",
          transition: "border-color 0.15s",
        }}
      >
        {DEVICE_ICON[node.deviceType] ?? DEVICE_ICON.unknown}
      </div>
      <span
        style={{
          fontSize: 11, color: "var(--ares-text)", fontFamily: "JetBrains Mono, monospace",
          maxWidth: 90, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}
      >
        {node.name}
      </span>
    </button>
  );
}
