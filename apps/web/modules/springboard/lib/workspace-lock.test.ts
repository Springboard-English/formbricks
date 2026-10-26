import { describe, expect, test, vi } from "vitest";
import { OperationNotAllowedError } from "@formbricks/types/errors";
import { assertSpringboardWorkspaceCreationAllowed } from "./workspace-lock";

vi.mock("./runtime-config", () => ({ isSpringboardSingleWorkspace: vi.fn(() => false) }));

const txWith = (count: number) => ({ workspace: { count: vi.fn().mockResolvedValue(count) } }) as never;

describe("single-workspace lock", () => {
  test("off: nothing is checked", async () => {
    const tx = txWith(5);
    await expect(assertSpringboardWorkspaceCreationAllowed(tx, "org1", false)).resolves.toBeUndefined();
    expect((tx as { workspace: { count: ReturnType<typeof vi.fn> } }).workspace.count).not.toHaveBeenCalled();
  });

  test("on: an organization's first workspace is still allowed", async () => {
    await expect(assertSpringboardWorkspaceCreationAllowed(txWith(0), "org1", true)).resolves.toBeUndefined();
  });

  test("on: a second workspace is refused on the server", async () => {
    await expect(assertSpringboardWorkspaceCreationAllowed(txWith(1), "org1", true)).rejects.toBeInstanceOf(
      OperationNotAllowedError
    );
  });

  test("reads SPRINGBOARD_SINGLE_WORKSPACE by default (unset = off)", async () => {
    await expect(assertSpringboardWorkspaceCreationAllowed(txWith(3), "org1")).resolves.toBeUndefined();
  });
});
