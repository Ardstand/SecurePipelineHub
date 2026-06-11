import React from "react";
import { NavLink, BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import FindingsTable from "./components/FindingsTable";
import FindingDetail from "./components/FindingDetail";
import ComplianceView from "./components/ComplianceView";
import TrendsView from "./components/TrendsView";

function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6l-8-4z"
        fill="rgba(79,142,247,0.18)"
        stroke="#4f8ef7"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="#4f8ef7"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function NavItem({ to, end, children }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `relative px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
          isActive
            ? "text-[#f0f4ff] bg-[#1a2948] border border-[#2a4070]"
            : "text-[#7e8fa8] hover:text-[#c8d4f0] hover:bg-[#121c2e]"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen" style={{ backgroundColor: "var(--bg-base)" }}>
        {/* Top navbar */}
        <header
          style={{
            backgroundColor: "var(--bg-surface)",
            borderBottom: "1px solid var(--border)",
          }}
          className="sticky top-0 z-10"
        >
          <div className="accent-line" />
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
            <div className="flex items-center gap-2.5">
              <ShieldIcon />
              <NavLink to="/" className="flex items-baseline gap-1.5">
                <span
                  style={{ fontFamily: "var(--font-sans)", letterSpacing: "-0.02em" }}
                  className="font-semibold text-[15px] text-[#f0f4ff]"
                >
                  SecurePipeline
                </span>
                <span
                  style={{ color: "var(--accent)" }}
                  className="text-[13px] font-medium"
                >
                  Hub
                </span>
              </NavLink>
            </div>
            <nav className="flex items-center gap-1">
              <NavItem to="/" end>Dashboard</NavItem>
              <NavItem to="/findings">Findings</NavItem>
              <NavItem to="/compliance">OWASP Coverage</NavItem>
              <NavItem to="/trends">Trends</NavItem>
            </nav>
          </div>
        </header>

        <main className="mx-auto max-w-7xl px-6 py-7">
          <Routes>
            <Route path="/"            element={<Dashboard />} />
            <Route path="/findings"    element={<FindingsTable />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/compliance"  element={<ComplianceView />} />
            <Route path="/trends"      element={<TrendsView />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
