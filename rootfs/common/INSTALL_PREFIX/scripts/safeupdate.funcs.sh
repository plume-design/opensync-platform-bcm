#!/bin/sh

# Subset of OSP error codes, see core/src/lib/osp/inc/osp_upg.h for more info
OSP_UPG_FL_ERASE=8
OSP_UPG_FL_WRITE=9
OSP_UPG_BC_SET=11

upg_image_write()
{
    format_alt_overlay || exit $OSP_UPG_FL_ERASE
    bcm_flasher "$1" || exit $OSP_UPG_FL_WRITE
}

upg_image_commit()
{
    bcm_bootstate 1 || exit $OSP_UPG_BC_SET
}

format_alt_overlay()
{
    if readlink /dev/root | grep -q "mmcblk"; then
        # Booted from eMMC
        echo "Skip formatting eMMC overlay partition"
    else
        # Booted from NAND
        if grep -sq '"loader"' /proc/mtd; then
            # New flash layout (with the "loader" partition)
            echo "Formatting NAND overlay partition"
            format_nand_alt_overlay || {
                echo "Failed to format NAND overlay"
                return 1
            }
        else
            # Legacy flash layout
            echo "Skip format of NAND overlay partition (legacy flash layout)"
        fi
    fi
}

format_nand_alt_overlay()
{
    # Get alternate boot partition based on the current boot partition.
    # Adapted from userspace/public/libs/bcm_flashutil/bcm_flashutil_nand.c::nandGetBootPartition()
    DEV_PREFIX="/dev/ubiblock0_"
    ROOTFS1_VOLID=4
    ROOTFS2_VOLID=6
    # Use get_rootfs_dev.sh script or fallback to reading /proc/environment/rootfs_opts
    boot_dev=$(/etc/get_rootfs_dev.sh ||
               grep -o "${DEV_PREFIX}[0-9]" /proc/environment/rootfs_opts)
    if [ "$boot_dev" = "${DEV_PREFIX}${ROOTFS1_VOLID}" ]; then
        boot_id=1
        alt_id=2
        alt_overlay_vol_id=25
    elif [ "$boot_dev" = "${DEV_PREFIX}${ROOTFS2_VOLID}" ]; then
        boot_id=2
        alt_id=1
        alt_overlay_vol_id=24
    else
        echo "Cannot detect boot partition from '$boot_dev'"
        return 1
    fi
    alt_overlay_vol_name="rootfs${alt_id}_overlay"

    # Get the size of the overlay volume in bytes
    vol_size=$(ubinfo /dev/ubi0 --vol_id=$alt_overlay_vol_id |
                grep "Size:" |                  # Size: 413 LEBs (104882176 bytes, 100.0 MiB)
                 awk -F'[()]' '{print $2}' |    # 104882176 bytes, 100.0 MiB
                  awk '{print $1}')             # 104882176
    if [ -z "$vol_size" ] || ! [ "$vol_size" -eq "$vol_size" ]; then  # Make sure vol_size is a number
        echo "Could not parse existing volume size, using default 100MiB"
        vol_size="100MiB"
    fi

    # Recreate the volume
    echo "Removing overlay volume $alt_overlay_vol_id (boot_id=$boot_id, alt_id=$alt_id)"
    ubirmvol /dev/ubi0 --vol_id=$alt_overlay_vol_id || {
        echo "Failed to remove overlay volume $alt_overlay_vol_id"
        # Fall-through to create it in any case
    }
    echo "Creating overlay volume $alt_overlay_vol_id ($alt_overlay_vol_name) with size $vol_size"
    ubimkvol /dev/ubi0 --size="$vol_size" --vol_id="$alt_overlay_vol_id" --name="$alt_overlay_vol_name" || {
        echo "Failed to create overlay volume $alt_overlay_vol_id ($alt_overlay_vol_name) with size $vol_size"
        return 1
    }
}
