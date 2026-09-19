// Tests for the two useEffect sites that react-hooks/set-state-in-effect
// flagged in App.jsx, added alongside the fixes so the behaviour they describe
// is pinned rather than argued about.
//
// The IOC type is now derived during render with an explicit analyst pick
// taking precedence, instead of being written by an effect keyed on [ioc]; the
// Cases list now loads through a cancellable promise instead of calling a
// state-setting function synchronously in an effect body.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";

const iocInput = () => screen.getByPlaceholderText(/8\.8\.8\.8/);
const typeSelect = () => screen.getByRole("combobox");
const runTriage = () => screen.getByRole("button", { name: /Run Triage/ });
const casesTab = () => screen.getByRole("button", { name: /^Cases$/ });

/** A complete TriageResponse, so the report view renders instead of throwing. */
const TRIAGE_RESPONSE = {
  case_id: "ABC123",
  status: "success",
  enrichment: {
    ioc: "evil.example.com",
    ioc_type: "url",
    verdict: "malicious",
    score: 87,
    engines: [{ id: "virustotal", verdict: "malicious", detail: "12/90" }],
  },
  report: {
    title: "Suspicious outbound connection",
    severity: "high",
    summary: "Test summary.",
    affected_assets: ["WS-042"],
    threat_type: "C2",
    ioc: "evil.example.com",
    ioc_type: "url",
    verdict: "malicious",
    score: 87,
    mitre_techniques: [],
    recommended_actions: ["Isolate the host."],
    playbook: ["Verify", "Contain"],
    generated_at: "2026-09-18T00:00:00Z",
  },
};

/** Route every fetch by URL, so one stub serves health, cases and triage. */
function installFetch({ cases = [], onTriage } = {}) {
  const calls = [];
  const stub = vi.fn(async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith("/health")) {
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }
    if (String(url).includes("/api/cases")) {
      return new Response(JSON.stringify(cases), { status: 200 });
    }
    if (String(url).includes("/api/triage")) {
      return new Response(JSON.stringify(onTriage ?? TRIAGE_RESPONSE), {
        status: 200,
      });
    }
    return new Response("{}", { status: 200 });
  });
  vi.stubGlobal("fetch", stub);
  return calls;
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("IOC type derivation", () => {
  it.each([
    ["8.8.8.8", "IP"],
    ["malware.example.com", "DOMAIN"],
    ["https://evil.example.com/x", "URL"],
    ["d41d8cd98f00b204e9800998ecf8427e", "HASH"],
  ])("detects %s as %s while typing", async (value, expected) => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), value);

    expect(typeSelect()).toHaveValue(expected);
  });

  it("lets an explicit pick override what the indicator looks like", async () => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "evil.example.com");
    expect(typeSelect()).toHaveValue("DOMAIN");

    await user.selectOptions(typeSelect(), "URL");

    expect(typeSelect()).toHaveValue("URL");
  });

  it("sends the analyst's override, not the detected type", async () => {
    const calls = installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "evil.example.com");
    await user.selectOptions(typeSelect(), "URL");
    await user.click(runTriage());

    const triage = await waitFor(() => {
      const call = calls.find(c => c.url.includes("/api/triage"));
      expect(call).toBeDefined();
      return call;
    });
    expect(JSON.parse(triage.options.body)).toMatchObject({
      ioc: "evil.example.com",
      ioc_type: "url",
    });
  });

  it("returns to auto-detection once a new indicator is typed", async () => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "evil.example.com");
    await user.selectOptions(typeSelect(), "URL");
    expect(typeSelect()).toHaveValue("URL");

    // Typing a genuinely new indicator hands control back to detection. The
    // reset lives in the input's change handler, so it happens for a real edit
    // and not merely because the component re-rendered.
    await user.clear(iocInput());
    await user.type(iocInput(), "1.2.3.4");

    expect(typeSelect()).toHaveValue("IP");
  });

  it("keeps the pick across re-renders that do not touch the indicator", async () => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "evil.example.com");
    await user.selectOptions(typeSelect(), "HASH");

    // Typing in another field re-renders the tab without changing the IOC.
    await user.type(screen.getByPlaceholderText(/Paste the raw SIEM alert/), "noise");

    expect(typeSelect()).toHaveValue("HASH");
  });
});

describe("Cases list loading", () => {
  const CASE_ROW = {
    case_id: "CASE0001",
    ioc: "185.220.101.45",
    ioc_type: "ip",
    status: "open",
    severity: "high",
    created_at: "2026-09-18T00:00:00Z",
    updated_at: "2026-09-18T00:00:00Z",
    timeline: [],
  };

  it("loads and renders cases on mount", async () => {
    installFetch({ cases: [CASE_ROW] });
    const user = userEvent.setup();
    render(<App />);

    await user.click(casesTab());

    expect(await screen.findByText(/185\.220\.101\.45/)).toBeInTheDocument();
  });

  it("clears the loading state when the list comes back empty", async () => {
    installFetch({ cases: [] });
    const user = userEvent.setup();
    render(<App />);

    await user.click(casesTab());

    // The spinner text must go away even with nothing to show, which is what
    // the effect's .finally(setLoading(false)) is responsible for.
    await waitFor(() =>
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument()
    );
  });

  it("does not warn when the tab unmounts while the fetch is in flight", async () => {
    // The mount effect writes state from a promise callback, so a response that
    // lands after unmount would be a late write. The cancelled flag drops it.
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    vi.stubGlobal("fetch", vi.fn(async url => {
      if (String(url).endsWith("/health")) {
        return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
      }
      await pending;
      return new Response(JSON.stringify([CASE_ROW]), { status: 200 });
    }));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});

    const user = userEvent.setup();
    render(<App />);
    await user.click(casesTab());
    await user.click(screen.getByRole("button", { name: /Triage/ }));

    release(new Response("[]", { status: 200 }));
    await Promise.resolve();

    expect(errors).not.toHaveBeenCalled();
  });
});

// The backend now requires an API key on PATCH /api/cases/{id}/status, and a
// browser bundle cannot hold a secret, so the hosted build ships without one.
// Rather than offering a status button that can only ever return 401, the tab
// replaces the buttons with a note. These tests pin both halves: the note in
// place of the buttons when unkeyed, the buttons plus the header when keyed.
describe("Cases tab status buttons and the API key", () => {
  const WRITABLE_CASE = {
    case_id: "CASE0001",
    ioc: "185.220.101.45",
    ioc_type: "ip",
    status: "open",
    severity: "high",
    created_at: "2026-09-18T00:00:00Z",
    updated_at: "2026-09-18T00:00:00Z",
    report: {
      summary: "Outbound connection to a known C2 node.",
      mitre_techniques: [
        {
          technique_id: "T1071.001",
          technique_name: "Web Protocols",
          mitre_url: "https://attack.mitre.org/techniques/T1071/001/",
        },
      ],
    },
    timeline: [
      { timestamp: "2026-09-18T00:00:00Z", action: "Case opened", notes: null },
    ],
  };

  /** Open the Cases tab and expand the one seeded case. */
  async function expandTheCase(user) {
    await user.click(casesTab());
    await user.click(await screen.findByText(/185\.220\.101\.45/));
  }

  const statusButtons = () =>
    screen.queryAllByRole("button", { name: /^(open|in progress|escalated|closed)$/i });

  describe("with no key configured", () => {
    it("shows a note instead of the status buttons", async () => {
      installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      expect(
        await screen.findByText(/Changing a case requires an API key/i)
      ).toBeInTheDocument();
      expect(statusButtons()).toHaveLength(0);
    });

    it("links the note to the README's Authentication section", async () => {
      installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      const link = await screen.findByRole("link", {
        name: /How authentication works/i,
      });
      expect(link).toHaveAttribute(
        "href",
        "https://github.com/SalCyberAware/SOCTriage#authentication"
      );
    });

    it("leaves the rest of the case view intact", async () => {
      // The point of the note is that only the write control goes away. The
      // report, the MITRE techniques and the timeline all still render.
      installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      expect(
        await screen.findByText(/Outbound connection to a known C2 node/)
      ).toBeInTheDocument();
      expect(screen.getByText(/T1071\.001/)).toBeInTheDocument();
      expect(screen.getByText(/Case opened/)).toBeInTheDocument();
    });

    it("sends no PATCH at all", async () => {
      const calls = installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      expect(calls.filter(c => c.options?.method === "PATCH")).toHaveLength(0);
    });
  });

  describe("with a key configured", () => {
    it("renders the status buttons and no note", async () => {
      vi.stubEnv("VITE_API_KEY", "a-configured-key");
      installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      expect(statusButtons().length).toBeGreaterThan(0);
      expect(
        screen.queryByText(/Changing a case requires an API key/i)
      ).not.toBeInTheDocument();
    });

    it("sends the key in the X-API-Key header on a status change", async () => {
      vi.stubEnv("VITE_API_KEY", "a-configured-key");
      const calls = installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);
      await user.click(screen.getByRole("button", { name: /^escalated$/i }));

      const patch = await waitFor(() => {
        const call = calls.find(c => c.options?.method === "PATCH");
        expect(call).toBeDefined();
        return call;
      });
      expect(patch.url).toContain("/api/cases/CASE0001/status");
      expect(patch.options.headers["X-API-Key"]).toBe("a-configured-key");
      expect(JSON.parse(patch.options.body)).toEqual({ status: "escalated" });
    });

    it("ignores a key that is only whitespace", async () => {
      // An env var set to "" or " " in a deploy config is a key that is not
      // configured, not a key of one space.
      vi.stubEnv("VITE_API_KEY", "   ");
      installFetch({ cases: [WRITABLE_CASE] });
      const user = userEvent.setup();
      render(<App />);

      await expandTheCase(user);

      expect(
        await screen.findByText(/Changing a case requires an API key/i)
      ).toBeInTheDocument();
      expect(statusButtons()).toHaveLength(0);
    });
  });
});
