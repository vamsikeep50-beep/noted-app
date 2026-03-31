import axios from 'axios';

import { auth } from '../firebase';

const isProd = import.meta.env.PROD;
const API = axios.create({ baseURL: import.meta.env.VITE_API_URL || (isProd ? 'https://noted-backend-i1m3.onrender.com/api' : 'http://localhost:5000/api') });

API.interceptors.request.use(async (req) => {
  if (auth.currentUser) {
    const token = await auth.currentUser.getIdToken(true);
    req.headers.Authorization = `Bearer ${token}`;
  }
  return req;
});

API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.clear();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);


export const userAPI = {
  getProfile: () => API.get('/user'),
  updateProfile: (data) => API.put('/user', data),
  getQR: () => API.get('/user/qr'),
  upgrade: () => API.post('/user/upgrade'),
};

export const connectionsAPI = {
  getAll: (params) => API.get('/connections', { params }),
  getOne: (id) => API.get(`/connections/${id}`),
  create: (data) => API.post('/connections', data),
  update: (id, data) => API.put(`/connections/${id}`, data),
  delete: (id) => API.delete(`/connections/${id}`),
  setReminder: (id, reminder) => API.put(`/connections/${id}`, { reminder }),
  process: (id, data) => API.post(`/connections/${id}/process`, data),
  followUp: (id, status) => API.post(`/connections/${id}/followup`, { status }),
  export: () => API.get('/connections/export', { responseType: 'blob' }),
};

export const eventsAPI = {
  getAll: () => API.get('/events'),
  getOne: (id) => API.get(`/events/${id}`),
  create: (data) => API.post('/events', data),
  update: (id, data) => API.put(`/events/${id}`, data),
  delete: (id) => API.delete(`/events/${id}`),
  getQR: (id) => API.get(`/events/${id}/qr`),
  joinByToken: (token) => API.get(`/events/join/${token}`),
};

export const aiAPI = {
  ask: (query) => API.post('/ai/ask', { query }),
  suggestions: () => API.get('/ai/suggestions'),
};

export const insightsAPI = {
  get: () => API.get('/insights'),
};
