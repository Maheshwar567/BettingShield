package com.bettingshield.app.ui;

import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bettingshield.app.R;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class AppPickerAdapter extends RecyclerView.Adapter<AppPickerAdapter.ViewHolder> {

    public static class AppItem {
        public final String name;
        public final String packageName;
        public final Drawable icon;

        public AppItem(String name, String packageName, Drawable icon) {
            this.name = name;
            this.packageName = packageName;
            this.icon = icon;
        }
    }

    public interface OnAppSelectedListener {
        void onSelected(AppItem item);
    }

    private final List<AppItem> allApps = new ArrayList<>();
    private final List<AppItem> filteredApps = new ArrayList<>();
    private final OnAppSelectedListener listener;

    public AppPickerAdapter(List<AppItem> apps, OnAppSelectedListener listener) {
        this.listener = listener;
        if (apps != null) {
            this.allApps.addAll(apps);
            this.filteredApps.addAll(apps);
        }
    }

    public void filter(String query) {
        filteredApps.clear();
        if (query == null || query.trim().isEmpty()) {
            filteredApps.addAll(allApps);
        } else {
            String lower = query.trim().toLowerCase(Locale.ROOT);
            for (AppItem app : allApps) {
                if (app.name.toLowerCase(Locale.ROOT).contains(lower) ||
                    app.packageName.toLowerCase(Locale.ROOT).contains(lower)) {
                    filteredApps.add(app);
                }
            }
        }
        notifyDataSetChanged();
    }

    public int getFilteredCount() {
        return filteredApps.size();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app_picker, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        AppItem item = filteredApps.get(position);
        holder.tvAppLabel.setText(item.name);
        holder.tvAppPackage.setText(item.packageName);
        if (item.icon != null) {
            holder.ivAppIcon.setImageDrawable(item.icon);
        } else {
            holder.ivAppIcon.setImageResource(android.R.drawable.sym_def_app_icon);
        }

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onSelected(item);
            }
        });
    }

    @Override
    public int getItemCount() {
        return filteredApps.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView ivAppIcon;
        TextView tvAppLabel;
        TextView tvAppPackage;

        ViewHolder(View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.ivAppIcon);
            tvAppLabel = itemView.findViewById(R.id.tvAppLabel);
            tvAppPackage = itemView.findViewById(R.id.tvAppPackage);
        }
    }
}
