import React, { useEffect, useState } from "react";
import { signupUser, getUsers } from "../api";

export default function AdminUsersPage({ user }) {
  const [users, setUsers] = useState([]);
  const [email, setEmail] = useState("");
  const [githubEmail, setGithubEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadUsers() {
      try {
        const data = await getUsers();
        setUsers(data);
      } catch (err) {
        console.error(err);
      }
    }
    loadUsers();
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setMessage(null);
    setLoading(true);

    try {
      const created = await signupUser({
        email,
        github_email: githubEmail,
        password,
        role: "user",
      });
      setUsers((prev) => [...prev, created]);
      setMessage(`Created user ${created.email}`);
      setEmail("");
      setGithubEmail("");
      setPassword("");
    } catch (err) {
      setError(err.message || "Unable to create user");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="mb-8 rounded-3xl border border-[#2c3e5f] bg-[#0d1b33] p-7 shadow-xl shadow-black/20">
        <div className="mb-4 flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-white">
              Admin User Management
            </h1>
            <p className="text-sm text-[#9ab0d1]">
              Create users and attach a GitHub email to map commits to their
              account.
            </p>
          </div>
          <div className="rounded-2xl bg-[#071023] px-4 py-3 text-sm text-[#8da0c1]">
            Signed in as <strong>{user?.email}</strong>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="grid gap-4 md:grid-cols-3">
          <label className="flex flex-col gap-2 text-sm text-[#cbd4ed]">
            User Email
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-2xl border border-[#2c3e5f] bg-[#071825] px-4 py-3 text-sm text-white outline-none focus:border-[#4f8ef7]"
              placeholder="user@example.com"
            />
          </label>

          <label className="flex flex-col gap-2 text-sm text-[#cbd4ed]">
            GitHub Email
            <input
              value={githubEmail}
              onChange={(e) => setGithubEmail(e.target.value)}
              className="rounded-2xl border border-[#2c3e5f] bg-[#071825] px-4 py-3 text-sm text-white outline-none focus:border-[#4f8ef7]"
              placeholder="github@example.com"
            />
          </label>

          <label className="flex flex-col gap-2 text-sm text-[#cbd4ed]">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-2xl border border-[#2c3e5f] bg-[#071825] px-4 py-3 text-sm text-white outline-none focus:border-[#4f8ef7]"
              placeholder="Secure password"
            />
          </label>

          <div className="md:col-span-3">
            {message ? (
              <div className="rounded-2xl border border-[#2a5f33] bg-[#0d2c1f] p-4 text-sm text-[#b7f2d0]">
                {message}
              </div>
            ) : null}
            {error ? (
              <div className="rounded-2xl border border-[#7e2f38] bg-[#431a22] p-4 text-sm text-[#f8d7da]">
                {error}
              </div>
            ) : null}
          </div>

          <div className="md:col-span-3 flex items-center justify-between gap-4">
            <span className="text-sm text-[#8da0c1]">
              New users sign in with their username/email and password.
            </span>
            <button
              type="submit"
              disabled={loading}
              className="rounded-2xl bg-[#4f8ef7] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#719ce0] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Creating user…" : "Create user"}
            </button>
          </div>
        </form>
      </div>

      <div className="rounded-3xl border border-[#2c3e5f] bg-[#0d1b33] p-7 shadow-xl shadow-black/20">
        <h2 className="mb-4 text-xl font-semibold text-white">
          Existing Users
        </h2>
        <div className="space-y-4">
          {users.length === 0 ? (
            <div className="rounded-2xl border border-[#25324d] bg-[#07101f] p-4 text-sm text-[#8da0c1]">
              No users yet.
            </div>
          ) : (
            users.map((user) => (
              <div
                key={user.id}
                className="rounded-2xl border border-[#23314a] bg-[#07101f] px-4 py-4 text-sm text-[#d7e3ff]"
              >
                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="font-semibold">{user.email}</div>
                    <div className="text-[#8da0c1]">
                      GitHub email: {user.github_email || "Not set"}
                    </div>
                  </div>
                  <div className="text-xs uppercase tracking-wide text-[#6d81a0]">
                    {user.role}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
