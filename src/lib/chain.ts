import { sha256Hex } from "./hash.js";
import { chainExtensionMessage } from "./messages.js";
export function extendChain(p: {
  chainId: string;
  sequence: number;
  previousChainState: string;
  actionRecordHash: string;
}): string {
  return sha256Hex(chainExtensionMessage(p));
}
