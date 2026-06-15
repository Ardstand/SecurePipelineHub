import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5000",
});

// Attach JWT to every request
API.interceptors.request.use((config) => {
  const token = localStorage.getItem("authToken");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// On 401 — clear token and redirect to login
API.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("authToken");
      localStorage.removeItem("authUser");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  },
);

function unwrap(res) {
  return res?.data?.data ?? res?.data;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
export const login = ({ email, password }) =>
  API.post("/api/auth/login", { email, password }).then(unwrap);

export const getCurrentUser = () => API.get("/api/auth/me").then(unwrap);

export const changePassword = (current_password, new_password) =>
  API.post("/api/auth/change-password", {
    current_password,
    new_password,
  }).then(unwrap);

// ── Admin user management ─────────────────────────────────────────────────────
export const getUsers = () => API.get("/api/users").then(unwrap);

export const signupUser = (data) =>
  API.post("/api/auth/signup", data).then(unwrap);

export const updateUserById = (id, data) =>
  API.patch(`/api/users/${id}`, data).then(unwrap);

export const deleteUserById = (id) =>
  API.delete(`/api/users/${id}`).then(unwrap);

// ── Findings ──────────────────────────────────────────────────────────────────
export const getStats = () => API.get("/api/stats").then(unwrap);

export const getFindings = (params) =>
  API.get("/api/findings", { params }).then(unwrap);

export const getFinding = (id) => API.get(`/api/findings/${id}`).then(unwrap);

export const updateFinding = (id, data) =>
  API.patch(`/api/findings/${id}`, data).then(unwrap);

export const addComment = (id, { text }) =>
  API.post(`/api/findings/${id}/comments`, { text }).then(unwrap);

export const getCompliance = () => API.get("/api/compliance").then(unwrap);

export const getTrends = (days = 30) =>
  API.get("/api/trends", { params: { days } }).then(unwrap);
