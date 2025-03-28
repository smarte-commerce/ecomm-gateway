package com.winnguyen1905.gateway.persistance.entity;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "shops")
@DiscriminatorValue("shop")
public class EShop extends EUserCredentials {

  // @OneToMany(mappedBy = "shop", fetch = FetchType.LAZY, cascade = {
  // CascadeType.PERSIST, CascadeType.MERGE })
  // private List<ProductEntity> products;

  // @OneToMany(mappedBy = "shop", fetch = FetchType.LAZY)
  // private List<DiscountEntity> discount;

  // @OneToMany(mappedBy = "shop", fetch = FetchType.LAZY)
  // private List<InventoryEntity> inventories;

  // @OneToMany(mappedBy = "shop", fetch = FetchType.LAZY)
  // private List<OrderEntity> orders;

  // @OneToMany(mappedBy = "shop")
  // private List<CartEntity> carts;

  // public void addCarts(CartEntity cartEntity) {
  // this.carts.add(cartEntity);
  // }
}
