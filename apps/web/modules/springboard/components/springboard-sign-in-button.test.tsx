import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { SpringboardSignInButton } from "./springboard-sign-in-button";

const { signInSocial } = vi.hoisted(() => ({ signInSocial: vi.fn() }));
vi.mock("@/modules/auth/lib/auth-client", () => ({ authClient: { signIn: { social: signInSocial } } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

describe("SpringboardSignInButton", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  test("renders the Springboard button and starts the springboard provider flow", async () => {
    signInSocial.mockResolvedValue({ error: null });
    render(<SpringboardSignInButton returnToUrl="https://forms.springboard.vn/" />);

    fireEvent.click(screen.getByRole("button", { name: "auth.login.continue_with_springboard" }));

    await vi.waitFor(() =>
      expect(signInSocial).toHaveBeenCalledWith({
        provider: "springboard",
        callbackURL: "https://forms.springboard.vn/",
        errorCallbackURL: "/auth/login",
      })
    );
  });
});
