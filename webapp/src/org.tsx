import { createContext, useContext } from "react";
import type { Org } from "./types";

export const OrgContext = createContext<Org | null>(null);

export function useOrg(): Org {
  const org = useContext(OrgContext);
  if (!org) throw new Error("OrgContext not provided");
  return org;
}