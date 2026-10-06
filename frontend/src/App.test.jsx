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
// The source as text, to check what can and cannot end up in the bundle.
import APP_SOURCE from "./App.jsx?raw";

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
    ["2001:4860:4860::8888", "IP"],
  ])("detects %s as %s while typing", async (value, expected) => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), value);

    expect(typeSelect()).toHaveValue(expected);
  });

  it("shows the backend's reason when it rejects a triage", async () => {
    // The backend answers a stated type that does not fit the IOC with a 400
    // and a plain message; the form shows that, not just the status code.
    vi.stubGlobal("fetch", vi.fn(async url => {
      if (String(url).includes("/api/triage")) {
        return new Response(
          JSON.stringify({ detail: "ioc does not look like a valid ip. Check the value." }),
          { status: 400 }
        );
      }
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }));
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "evil.example.com");
    await user.selectOptions(typeSelect(), "IP");
    await user.click(runTriage());

    expect(await screen.findByText(/does not look like a valid ip/)).toBeInTheDocument();
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

// Case ownership: every call carries this browser's session token, and the
// admin key exists only when an operator types it in. There is no build-time
// key any more, because anything Vite inlines is public.
describe("Session token and admin key", () => {
  const OWN_CASE = {
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

  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const STORAGE_KEY = "soctriage.sessionToken";

  /** Open the Cases tab and expand the one seeded case. */
  async function expandTheCase(user) {
    await user.click(casesTab());
    await user.click(await screen.findByText(/185\.220\.101\.45/));
  }

  async function typeAdminKey(user, key) {
    await user.type(screen.getByPlaceholderText(/Admin API key/i), key);
    await user.click(screen.getByRole("button", { name: /Use key/i }));
  }

  const statusButtons = () =>
    screen.queryAllByRole("button", { name: /^(open|in progress|escalated|closed)$/i });

  beforeEach(() => {
    localStorage.clear();
  });

  it("creates a random token on first load and keeps it in localStorage", async () => {
    installFetch();
    render(<App />);

    await waitFor(() => expect(localStorage.getItem(STORAGE_KEY)).toMatch(UUID));
  });

  it("reuses the stored token instead of making a new one", async () => {
    localStorage.setItem(STORAGE_KEY, "11111111-1111-4111-8111-111111111111");
    const calls = installFetch();
    render(<App />);

    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(localStorage.getItem(STORAGE_KEY)).toBe("11111111-1111-4111-8111-111111111111");
    expect(calls[0].options.headers["X-Session-Token"]).toBe(
      "11111111-1111-4111-8111-111111111111"
    );
  });

  it("sends the token on every API call, and no key by default", async () => {
    const calls = installFetch({ cases: [OWN_CASE] });
    const user = userEvent.setup();
    render(<App />);

    await user.type(iocInput(), "8.8.8.8");
    await user.click(runTriage());
    await user.click(await screen.findByRole("button", { name: /New Triage/ }));
    await expandTheCase(user);
    await user.click(screen.getByRole("button", { name: /^escalated$/i }));
    await user.click(screen.getByRole("button", { name: /Dashboard/ }));

    await waitFor(() => {
      const paths = calls.map(c => new URL(c.url).pathname);
      for (const path of ["/health", "/api/triage", "/api/cases", "/api/cases/CASE0001/status", "/api/dashboard"]) {
        expect(paths).toContain(path);
      }
    });
    const token = localStorage.getItem(STORAGE_KEY);
    for (const call of calls) {
      expect(call.options.headers["X-Session-Token"]).toBe(token);
      expect(call.options.headers["X-API-Key"]).toBeUndefined();
    }
  });

  it("still works when localStorage is unavailable", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const calls = installFetch();
    render(<App />);

    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(calls[0].options.headers["X-Session-Token"]).toMatch(UUID);
  });

  it("tells visitors their cases are tied to this browser", () => {
    installFetch();
    render(<App />);

    expect(screen.getByText(/Cases you open are tied to this browser/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /How this works/i })).toHaveAttribute(
      "href",
      "https://github.com/SalCyberAware/SOCTriage#authentication"
    );
  });

  it("offers the status buttons on the visitor's own cases without any key", async () => {
    installFetch({ cases: [OWN_CASE] });
    const user = userEvent.setup();
    render(<App />);

    await expandTheCase(user);

    expect(statusButtons()).toHaveLength(4);
    expect(screen.getByText(/Outbound connection to a known C2 node/)).toBeInTheDocument();
  });

  it("sends a typed admin key and refetches the cases with it", async () => {
    const calls = installFetch({ cases: [OWN_CASE] });
    const user = userEvent.setup();
    render(<App />);
    await user.click(casesTab());
    await screen.findByText(/185\.220\.101\.45/);

    await typeAdminKey(user, "typed-at-runtime");

    await waitFor(() => {
      const keyed = calls.filter(
        c => c.url.endsWith("/api/cases") && c.options.headers["X-API-Key"] === "typed-at-runtime"
      );
      expect(keyed).toHaveLength(1);
    });
    expect(screen.getByText(/Admin key in use for this page/i)).toBeInTheDocument();
  });

  it("never stores the admin key", async () => {
    installFetch();
    const user = userEvent.setup();
    render(<App />);

    await typeAdminKey(user, "typed-at-runtime");

    const stored = Object.keys(localStorage).map(k => localStorage.getItem(k)).join(" ");
    expect(stored).not.toContain("typed-at-runtime");
    expect(Object.keys(sessionStorage)).toHaveLength(0);
  });

  it("stops sending the key once it is forgotten", async () => {
    const calls = installFetch({ cases: [OWN_CASE] });
    const user = userEvent.setup();
    render(<App />);
    await typeAdminKey(user, "typed-at-runtime");

    await user.click(screen.getByRole("button", { name: /Forget key/i }));
    await expandTheCase(user);
    await user.click(screen.getByRole("button", { name: /^closed$/i }));

    const patch = await waitFor(() => {
      const call = calls.find(c => c.options?.method === "PATCH");
      expect(call).toBeDefined();
      return call;
    });
    expect(patch.options.headers["X-API-Key"]).toBeUndefined();
    expect(patch.options.headers["X-Session-Token"]).toMatch(UUID);
  });

  it("builds no key into the bundle", () => {
    expect(APP_SOURCE).not.toMatch(/VITE_API_KEY/);
  });
});
