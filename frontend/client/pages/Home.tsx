import { useState, useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { colorAPI, Color } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Plus, Edit2, Trash2, Copy, Check } from "lucide-react";

export default function Home() {
  const { isAuthenticated } = useAuth();
  const [colors, setColors] = useState<Color[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    name: "",
    hex: "",
    image: null as File | null,
  });

  useEffect(() => {
    fetchColors();
  }, []);

  const fetchColors = async () => {
    try {
      setIsLoading(true);
      const data = await colorAPI.getAll();
      setColors(data);
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to fetch colors",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name || !formData.hex) {
      toast({
        title: "Error",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    try {
      if (editingId) {
        await colorAPI.update(
          editingId,
          formData.name,
          formData.hex,
          formData.image || undefined
        );
        toast({
          title: "Success",
          description: "Color updated successfully!",
        });
      } else {
        await colorAPI.create(
          formData.name,
          formData.hex,
          formData.image || undefined
        );
        toast({
          title: "Success",
          description: "Color added successfully!",
        });
      }
      setFormData({ name: "", hex: "", image: null });
      setEditingId(null);
      setShowForm(false);
      fetchColors();
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to save color",
        variant: "destructive",
      });
    }
  };

  const handleEdit = (color: Color) => {
    setFormData({
      name: color.color_name,
      hex: color.hex_code,
      image: null,
    });
    setEditingId(color.id);
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this color?")) return;

    try {
      await colorAPI.delete(id);
      toast({
        title: "Success",
        description: "Color deleted successfully!",
      });
      fetchColors();
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to delete color",
        variant: "destructive",
      });
    }
  };

  const copyToClipboard = (hex: string, id: string) => {
    navigator.clipboard.writeText(hex);
    setCopiedId(id);
    toast({
      title: "Copied!",
      description: `Color code ${hex} copied to clipboard`,
    });
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCancel = () => {
    setFormData({ name: "", hex: "", image: null });
    setEditingId(null);
    setShowForm(false);
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 px-4">
        <div className="text-center max-w-md">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Welcome to ColorHub
          </h1>
          <p className="text-gray-600 mb-8">
            Sign in to start managing your color palette. Create, organize, and
            share beautiful colors.
          </p>
          <div className="space-y-4">
            <Button
              onClick={() => (window.location.href = "/login")}
              className="w-full h-11 bg-gradient-to-r from-primary to-secondary text-white font-semibold"
            >
              Sign In
            </Button>
            <Button
              onClick={() => (window.location.href = "/register")}
              variant="outline"
              className="w-full h-11"
            >
              Create Account
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <div className="max-w-7xl mx-auto px-4 py-12">
        <div className="flex items-center justify-between mb-12">
          <div>
            <h1 className="text-4xl font-bold text-gray-900 mb-2">
              My Colors
            </h1>
            <p className="text-gray-600">
              Manage and organize your color palette
            </p>
          </div>
          <Button
            onClick={() => setShowForm(!showForm)}
            className="bg-gradient-to-r from-primary to-accent text-white font-semibold h-11 px-6"
          >
            <Plus className="h-5 w-5 mr-2" />
            {showForm ? "Cancel" : "Add Color"}
          </Button>
        </div>

        {showForm && (
          <div className="bg-white rounded-2xl shadow-lg p-8 mb-12">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">
              {editingId ? "Edit Color" : "Add New Color"}
            </h2>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Color Name *
                  </label>
                  <Input
                    type="text"
                    value={formData.name}
                    onChange={(e) =>
                      setFormData({ ...formData, name: e.target.value })
                    }
                    placeholder="e.g., Ocean Blue"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Hex Code *
                  </label>
                  <div className="flex gap-2">
                    <Input
                      type="text"
                      value={formData.hex}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          hex: e.target.value.toUpperCase(),
                        })
                      }
                      placeholder="#FF6B6B"
                      maxLength={7}
                    />
                    {formData.hex && (
                      <div
                        className="w-12 h-10 rounded-lg border border-gray-200 flex-shrink-0"
                        style={{ backgroundColor: formData.hex }}
                      />
                    )}
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Color Image (Optional)
                </label>
                <Input
                  type="file"
                  accept="image/*"
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      image: e.target.files?.[0] || null,
                    })
                  }
                />
              </div>

              <div className="flex gap-4">
                <Button
                  type="submit"
                  className="flex-1 bg-gradient-to-r from-primary to-secondary text-white font-semibold h-11"
                >
                  {editingId ? "Update Color" : "Add Color"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleCancel}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </form>
          </div>
        )}

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <p className="text-gray-600">Loading colors...</p>
          </div>
        ) : colors.length === 0 ? (
          <div className="bg-white rounded-2xl shadow-lg p-12 text-center">
            <p className="text-gray-600 text-lg mb-4">
              No colors yet. Add your first color to get started!
            </p>
            <Button
              onClick={() => setShowForm(true)}
              className="bg-gradient-to-r from-primary to-accent text-white font-semibold"
            >
              <Plus className="h-5 w-5 mr-2" />
              Add First Color
            </Button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {colors.map((color) => (
              <div
                key={color.id}
                className="bg-white rounded-2xl shadow-lg overflow-hidden hover:shadow-xl transition-shadow"
              >
                {color.image && (
                  <div className="w-full h-40 bg-gray-100 overflow-hidden">
                    <img
                      src={`/uploads/${color.image}`}
                      alt={color.color_name}
                      className="w-full h-full object-cover"
                    />
                  </div>
                )}
                <div
                  className="w-full h-24 bg-gradient-to-br"
                  style={{
                    backgroundColor: color.hex_code,
                  }}
                />
                <div className="p-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    {color.color_name}
                  </h3>
                  <div className="flex items-center gap-2 mb-6">
                    <code className="text-sm font-mono text-gray-600 bg-gray-100 px-3 py-1 rounded">
                      {color.hex_code}
                    </code>
                    <button
                      onClick={() => copyToClipboard(color.hex_code, color.id)}
                      className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                      {copiedId === color.id ? (
                        <Check className="h-4 w-4 text-green-600" />
                      ) : (
                        <Copy className="h-4 w-4 text-gray-600" />
                      )}
                    </button>
                  </div>
                  <div className="flex gap-3">
                    <Button
                      onClick={() => handleEdit(color)}
                      variant="outline"
                      className="flex-1 h-9"
                    >
                      <Edit2 className="h-4 w-4 mr-2" />
                      Edit
                    </Button>
                    <Button
                      onClick={() => handleDelete(color.id)}
                      variant="outline"
                      className="flex-1 h-9 text-red-600 hover:text-red-700 hover:border-red-200"
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
