import type { HostStatus } from "./session";

export interface SubnetScanNode {
  id: string;
  ip: string;
  name: string;
  deviceType: string;
  hostStatus: HostStatus;
}

export interface SubnetScanTopology {
  macrosessionId: string;
  cidr: string;
  hostStatusSummary: Record<string, number>;
  nodes: SubnetScanNode[];
}
