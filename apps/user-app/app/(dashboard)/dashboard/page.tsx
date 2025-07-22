import React from "react";

export default function Dashboard() {
  return (
    <div className="flex h-screen">
      <div className="flex-1 p-8">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-3xl font-bold text-gray-800 mb-4">Dashboard</h2>
          <p className="text-lg text-gray-600">
            Welcome to your dashboard! Here you can manage your tasks, view
            analytics, and more.
          </p>

          <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Cards */}
            <div className="bg-blue-500 p-6 rounded-lg shadow-lg text-white">
              <h3 className="text-xl font-semibold">Analytics</h3>
              <p className="mt-4">
                View detailed analytics of your progress and trends.
              </p>
            </div>

            <div className="bg-green-500 p-6 rounded-lg shadow-lg text-white">
              <h3 className="text-xl font-semibold">Tasks</h3>
              <p className="mt-4">
                Manage your tasks and to-do lists effectively.
              </p>
            </div>

            <div className="bg-yellow-500 p-6 rounded-lg shadow-lg text-white">
              <h3 className="text-xl font-semibold">Messages</h3>
              <p className="mt-4">
                Keep track of your recent messages and notifications.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
