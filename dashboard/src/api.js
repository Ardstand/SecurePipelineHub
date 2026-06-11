import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5000",
});

// Flask API wraps responses like: { status: "success", data: ... }
function unwrap(response) {
  return response?.data?.data ?? response?.data;
}

export const getStats = () => API.get("/api/stats").then(unwrap);

export const getFindings = (params) =>
  API.get("/api/findings", { params }).then(unwrap);

export const getFinding = (id) => API.get(`/api/findings/${id}`).then(unwrap);

export const updateFinding = (id, data) =>
  API.patch(`/api/findings/${id}`, data).then(unwrap);

export const addComment = (id, { text, author }) =>
  API.post(`/api/findings/${id}/comments`, { text, author }).then(unwrap);

export const getCompliance = () => API.get("/api/compliance").then(unwrap);

export const getTrends = (days = 30) =>
  API.get("/api/trends", { params: { days } }).then(unwrap);
