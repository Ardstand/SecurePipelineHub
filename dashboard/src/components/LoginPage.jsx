import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../api";

export default function LoginPage({ onLogin }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await login({ email, password });
      onLogin(data);
      setLoading(false);
      navigate(data.user.role === "admin" ? "/admin/users" : "/", {
        replace: true,
      });
    } catch (err) {
      setLoading(false);
      setError(err.message || "Login failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#07131f] px-4 py-10">
      <div className="w-full max-w-md rounded-2xl border border-[#29364f] bg-[#0d1b33] p-8 shadow-xl shadow-black/20">
        <h1 className="mb-6 text-center text-3xl font-semibold text-white">
          SecurePipeline Login
        </h1>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-[#a8b7d5]">
              Username / Email
            </label>
            <input
              type="text"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-xl border border-[#2c3e5f] bg-[#0b192f] px-4 py-3 text-sm text-white outline-none transition focus:border-[#4f8ef7]"
              placeholder="admin or your email"
            />
          </div>

          <div>
            <label className="mb-2 block text-sm font-medium text-[#a8b7d5]">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-[#2c3e5f] bg-[#0b192f] px-4 py-3 text-sm text-white outline-none transition focus:border-[#4f8ef7]"
              placeholder="Enter your password"
            />
          </div>

          {error ? (
            <div className="rounded-xl border border-[#7e2f38] bg-[#431a22] px-4 py-3 text-sm text-[#f8d7da]">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-[#4f8ef7] px-4 py-3 text-sm font-semibold text-white transition hover:bg-[#719ce0] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Logging in…" : "Login as Admin"}
          </button>
        </form>

        <div className="mt-5 text-center text-sm text-[#8da0c1]">
          Use <strong>admin</strong> / <strong>admin</strong> to log in as the
          initial admin account (testing).
        </div>
      </div>
    </div>
  );
}
