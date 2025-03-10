import { UserLogin } from "../interfaces/UserLogin";

interface LoginResponse {
  token: string;
  }

const login = async (userInfo: UserLogin) => {
  // TODO: make a POST request to the login route
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      
    },
    body: JSON.stringify(userInfo),
  });
  if (!response.ok) {
    throw new Error('Login failed');
}

const data: LoginResponse = await response.json();
return data;
}



export { login };
