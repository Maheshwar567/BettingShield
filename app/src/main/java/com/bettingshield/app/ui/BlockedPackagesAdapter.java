package com.bettingshield.app.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlockedPackage;

import java.util.ArrayList;
import java.util.List;

/**
 * RecyclerView adapter for displaying and removing blocked betting apps.
 */
public class BlockedPackagesAdapter extends RecyclerView.Adapter<BlockedPackagesAdapter.ViewHolder> {

    public interface OnDeleteClickListener {
        void onDelete(BlockedPackage pkg);
    }

    private final List<BlockedPackage> packageList = new ArrayList<>();
    private final OnDeleteClickListener deleteClickListener;

    public BlockedPackagesAdapter(OnDeleteClickListener listener) {
        this.deleteClickListener = listener;
    }

    public void setPackages(List<BlockedPackage> packages) {
        packageList.clear();
        if (packages != null) {
            packageList.addAll(packages);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_package, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        BlockedPackage item = packageList.get(position);
        holder.tvAppName.setText(item.getAppName());
        holder.tvPackageName.setText(item.getPackageName());
        holder.btnDelete.setOnClickListener(v -> {
            if (deleteClickListener != null) {
                deleteClickListener.onDelete(item);
            }
        });
    }

    @Override
    public int getItemCount() {
        return packageList.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvAppName;
        TextView tvPackageName;
        ImageButton btnDelete;

        ViewHolder(View itemView) {
            super(itemView);
            tvAppName = itemView.findViewById(R.id.tvAppName);
            tvPackageName = itemView.findViewById(R.id.tvPackageName);
            btnDelete = itemView.findViewById(R.id.btnDeletePackage);
        }
    }
}
