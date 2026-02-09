// This function is a generic API request handler.
// It automatically adds the Authorization header to requests
// if a token is found in localStorage.

export const apiRequest = async (url: string, options: RequestInit = {}) => {
  // Assuming the token is stored in localStorage.
  // If you store it elsewhere (e.g., sessionStorage, cookies),
  // you'll need to update this line.
  const token = localStorage.getItem('authToken');

  const headers: HeadersInit = {
    ...options.headers,
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.message || 'API request failed');
  }

  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return res.json();
  }

  return {};
};
