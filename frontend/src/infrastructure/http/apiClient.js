import axios from 'axios';
import setupAuthInterceptor from './interceptors/authInterceptor';

const apiClient = axios.create({
    baseURL: import.meta.env.VITE_API_URL,
});

setupAuthInterceptor(apiClient);
export default apiClient;