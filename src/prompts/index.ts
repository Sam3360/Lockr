import { confirm, input, password } from "@inquirer/prompts";
import type { Credential } from "../types.js";

export async function masterPassword(message = "Master password:"): Promise<string> { return password({ message, mask: "*" }); }
export async function authenticate(): Promise<string> { return masterPassword(); }
export async function credentialInput(existing?: Credential): Promise<Omit<Credential, "id" | "createdAt" | "updatedAt">> {
  const field = async (message: string, value = "", required = false) => input({ message, default: value, validate: v => !required || v.trim() ? true : "This field is required." });
  return {
    service: (await field("Service name:", existing?.service, true)).trim(),
    username: (await field("Username:", existing?.username, true)).trim(),
    password: await password({ message: "Password (leave blank to keep current):", mask: "*" }) || existing?.password || "",
    website: (await field("Website:", existing?.website)).trim() || undefined,
    notes: await input({ message: "Notes:", default: existing?.notes }),
    category: (await field("Category:", existing?.category)).trim() || undefined,
    tags: (await field("Tags (comma-separated):", existing?.tags.join(", "))).split(",").map(x => x.trim()).filter(Boolean)
  };
}
export { confirm };
