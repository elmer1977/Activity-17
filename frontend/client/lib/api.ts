export interface Color {
  id: string;
  color_name: string;
  hex_code: string;
  image?: string;
}

export interface UserProfile {
  id: string;
  email: string;
  profile_image?: string;
}

const getAuthHeaders = () => {
  const token = localStorage.getItem("authToken");
  return {
    ...(token && { Authorization: token }),
  };
};

// Colors API
export const colorAPI = {
  async getAll(): Promise<Color[]> {
    const response = await fetch("/api/colors");
    if (!response.ok) throw new Error("Failed to fetch colors");
    return response.json();
  },

  async create(
    colorName: string,
    hexCode: string,
    image?: File
  ): Promise<{ message: string }> {
    const formData = new FormData();
    formData.append("color_name", colorName);
    formData.append("hex_code", hexCode);
    if (image) formData.append("image", image);

    const response = await fetch("/api/colors", {
      method: "POST",
      headers: getAuthHeaders(),
      body: formData,
    });

    if (!response.ok) throw new Error("Failed to create color");
    return response.json();
  },

  async update(
    id: string,
    colorName: string,
    hexCode: string,
    image?: File
  ): Promise<{ message: string }> {
    const formData = new FormData();
    formData.append("color_name", colorName);
    formData.append("hex_code", hexCode);
    if (image) formData.append("image", image);

    const response = await fetch(`/api/colors/${id}`, {
      method: "PUT",
      headers: getAuthHeaders(),
      body: formData,
    });

    if (!response.ok) throw new Error("Failed to update color");
    return response.json();
  },

  async delete(id: string): Promise<{ message: string }> {
    const response = await fetch(`/api/colors/${id}`, {
      method: "DELETE",
      headers: getAuthHeaders(),
    });

    if (!response.ok) throw new Error("Failed to delete color");
    return response.json();
  },
};

// Profile API
export const profileAPI = {
  async update(
    email: string,
    profileImage?: File
  ): Promise<{ message: string }> {
    const formData = new FormData();
    formData.append("email", email);
    if (profileImage) formData.append("image", profileImage);

    const response = await fetch("/api/profile", {
      method: "PUT",
      headers: getAuthHeaders(),
      body: formData,
    });

    if (!response.ok) throw new Error("Failed to update profile");
    return response.json();
  },
};
