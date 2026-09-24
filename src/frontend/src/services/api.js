import axios from 'axios';

const API_BASE = '/api';

export const api = {
  analyzeFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await axios.post(`${API_BASE}/analyze`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  analyzeBatch: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await axios.post(`${API_BASE}/batch`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  getHistory: async (skip = 0, limit = 20) => {
    const response = await axios.get(`${API_BASE}/history?skip=${skip}&limit=${limit}`);
    return response.data;
  },

  getAnalysis: async (id) => {
    const response = await axios.get(`${API_BASE}/analysis/${id}`);
    return response.data;
  },

  deleteAnalysis: async (id) => {
    const response = await axios.delete(`${API_BASE}/analysis/${id}`);
    return response.data;
  },

  getHealth: async () => {
    const response = await axios.get(`${API_BASE}/health`);
    return response.data;
  },

  getModelInfo: async () => {
    const response = await axios.get(`${API_BASE}/model-info`);
    return response.data;
  },

  getReport: async (id) => {
    const response = await axios.get(`${API_BASE}/report/${id}`, {
      responseType: 'blob'
    });
    return response.data;
  }
};
