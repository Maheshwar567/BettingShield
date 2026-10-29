package com.bettingshield.app.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlockedDomain;

import java.util.ArrayList;
import java.util.List;

/**
 * RecyclerView adapter for displaying and deleting custom domain exceptions.
 */
public class BlockedDomainsAdapter extends RecyclerView.Adapter<BlockedDomainsAdapter.ViewHolder> {

    public interface OnDeleteClickListener {
        void onDelete(BlockedDomain domain);
    }

    private final List<BlockedDomain> domainList = new ArrayList<>();
    private final OnDeleteClickListener deleteClickListener;

    public BlockedDomainsAdapter(OnDeleteClickListener listener) {
        this.deleteClickListener = listener;
    }

    public void setDomains(List<BlockedDomain> domains) {
        domainList.clear();
        if (domains != null) {
            domainList.addAll(domains);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_domain, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        BlockedDomain item = domainList.get(position);
        holder.tvDomainName.setText(item.getDomain());
        holder.btnDelete.setOnClickListener(v -> {
            if (deleteClickListener != null) {
                deleteClickListener.onDelete(item);
            }
        });
    }

    @Override
    public int getItemCount() {
        return domainList.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvDomainName;
        ImageButton btnDelete;

        ViewHolder(View itemView) {
            super(itemView);
            tvDomainName = itemView.findViewById(R.id.tvDomainName);
            btnDelete = itemView.findViewById(R.id.btnDeleteDomain);
        }
    }
}
