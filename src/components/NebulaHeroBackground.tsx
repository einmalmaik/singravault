// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Canvas-based nebula/starfield background
 *
 * Ported from singra-core-ai design system.
 * Variant "landing" → landing hero (right-side glow, no text).
 * Variant "panel"   → auth brand panel (blackhole + accretion disk + "VAULT" text).
 */

import { useEffect, useRef } from "react";

type NebulaVariant = "landing" | "panel";

interface NebulaHeroBackgroundProps {
    textScale?: number;
    showText?: boolean;
    showParticles?: boolean;
    variant?: NebulaVariant;
}

interface Star {
    x: number;
    y: number;
    size: number;
    opacity: number;
    twinkle: number;
    phase: number;
    driftX: number;
    driftY: number;
}

interface MistCloud {
    orbitRadius: number;
    orbitAngle: number;
    yOffset: number;
    radius: number;
    opacity: number;
    hue: number;
    saturation: number;
    lightness: number;
    drift: number;
    phase: number;
    anchor: number;
    stretchX: number;
    stretchY: number;
    rotation: number;
    density: number;
    glow: number;
}

interface AccretionParticle {
    angle: number;
    radius: number;
    speed: number;
    size: number;
    opacity: number;
    axis: number;
    hue: number;
}

const TAU = Math.PI * 2;

export function NebulaHeroBackground({
    textScale = 1,
    showText = true,
    showParticles = true,
    variant = "panel",
}: NebulaHeroBackgroundProps) {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const stars: Star[] = [];
        const clouds: MistCloud[] = [];
        const particles: AccretionParticle[] = [];

        let animationId = 0;
        let focusX = 0;
        let focusY = 0;
        let holeRadius = 0;
        let ringRadius = 0;

        const particleCount = variant === "landing" ? 96 : 44;

        const resetParticle = (particle: AccretionParticle) => {
            particle.angle = Math.random() * TAU;
            particle.radius = ringRadius * (0.78 + Math.random() * 0.72);
            particle.speed = 0.006 + Math.random() * 0.01;
            particle.size = 0.6 + Math.random() * 1.6;
            particle.opacity = 0.18 + Math.random() * 0.48;
            particle.axis = 0.26 + Math.random() * 0.16;
            particle.hue = 205 + Math.random() * 18;
        };

        const resize = () => {
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            canvas.width = canvas.offsetWidth * dpr;
            canvas.height = canvas.offsetHeight * dpr;
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.scale(dpr, dpr);
            initScene();
        };

        const initScene = () => {
            const width = canvas.offsetWidth;
            const height = canvas.offsetHeight;

            focusX = width * (variant === "landing" ? 0.9 : 0.68);
            focusY = height * (variant === "landing" ? 0.48 : 0.4);
            holeRadius = Math.min(width, height) * (variant === "landing" ? 0.14 : 0.085);
            ringRadius = holeRadius * 2.35;

            stars.length = 0;
            clouds.length = 0;
            particles.length = 0;

            const starCount = variant === "landing" ? 130 : 72;
            for (let index = 0; index < starCount; index += 1) {
                stars.push({
                    x: Math.random() * width,
                    y: Math.random() * height,
                    size: 0.35 + Math.random() * 1.6,
                    opacity: 0.08 + Math.random() * 0.42,
                    twinkle: 0.3 + Math.random() * 0.9,
                    phase: Math.random() * TAU,
                    driftX: (Math.random() - 0.5) * 0.03,
                    driftY: (Math.random() - 0.5) * 0.02,
                });
            }

            const outerClouds = variant === "landing" ? 16 : 10;
            for (let index = 0; index < outerClouds; index += 1) {
                clouds.push({
                    orbitRadius: width * (0.18 + Math.random() * 0.34),
                    orbitAngle: Math.random() * TAU,
                    yOffset: (Math.random() - 0.5) * height * 0.48,
                    radius: 150 + Math.random() * (variant === "landing" ? 260 : 180),
                    opacity: 0.035 + Math.random() * 0.06,
                    hue: 208 + Math.random() * 20,
                    saturation: 18 + Math.random() * 18,
                    lightness: 52 + Math.random() * 18,
                    drift: 0.06 + Math.random() * 0.12,
                    phase: Math.random() * TAU,
                    anchor: 0.72 + Math.random() * 0.2,
                    stretchX: 1.18 + Math.random() * 0.44,
                    stretchY: 0.7 + Math.random() * 0.34,
                    rotation: (Math.random() - 0.5) * 0.55,
                    density: 0.88 + Math.random() * 0.44,
                    glow: 0.76 + Math.random() * 0.34,
                });
            }

            const leftFogCount = variant === "landing" ? 7 : 4;
            for (let index = 0; index < leftFogCount; index += 1) {
                clouds.push({
                    orbitRadius: width * (0.12 + Math.random() * 0.18),
                    orbitAngle: Math.random() * TAU,
                    yOffset: (Math.random() - 0.5) * height * 0.58,
                    radius: 120 + Math.random() * 160,
                    opacity: 0.018 + Math.random() * 0.032,
                    hue: 216 + Math.random() * 10,
                    saturation: 12 + Math.random() * 12,
                    lightness: 32 + Math.random() * 12,
                    drift: 0.04 + Math.random() * 0.08,
                    phase: Math.random() * TAU,
                    anchor: 0.18 + Math.random() * 0.2,
                    stretchX: 1.22 + Math.random() * 0.38,
                    stretchY: 0.78 + Math.random() * 0.24,
                    rotation: (Math.random() - 0.5) * 0.42,
                    density: 0.72 + Math.random() * 0.24,
                    glow: 0.5 + Math.random() * 0.2,
                });
            }

            if (variant === "landing") {
                const plumeCount = 8;
                for (let index = 0; index < plumeCount; index += 1) {
                    clouds.push({
                        orbitRadius: width * (0.08 + Math.random() * 0.14),
                        orbitAngle: Math.random() * TAU,
                        yOffset: (Math.random() - 0.5) * height * 0.36,
                        radius: 180 + Math.random() * 220,
                        opacity: 0.05 + Math.random() * 0.045,
                        hue: 205 + Math.random() * 10,
                        saturation: 16 + Math.random() * 10,
                        lightness: 66 + Math.random() * 12,
                        drift: 0.08 + Math.random() * 0.1,
                        phase: Math.random() * TAU,
                        anchor: 0.76 + Math.random() * 0.16,
                        stretchX: 1.42 + Math.random() * 0.4,
                        stretchY: 0.54 + Math.random() * 0.18,
                        rotation: (Math.random() - 0.5) * 0.34,
                        density: 1 + Math.random() * 0.5,
                        glow: 0.98 + Math.random() * 0.28,
                    });
                }
            }

            if (showParticles) {
                for (let index = 0; index < particleCount; index += 1) {
                    const particle: AccretionParticle = {
                        angle: 0, radius: 0, speed: 0, size: 0, opacity: 0, axis: 0, hue: 0,
                    };
                    resetParticle(particle);
                    particles.push(particle);
                }
            }
        };

        const drawBase = (width: number, height: number) => {
            const backgroundGradient = ctx.createLinearGradient(0, 0, 0, height);
            backgroundGradient.addColorStop(0, "hsl(228 26% 3%)");
            backgroundGradient.addColorStop(0.4, "hsl(224 24% 4%)");
            backgroundGradient.addColorStop(1, "hsl(220 20% 4%)");
            ctx.fillStyle = backgroundGradient;
            ctx.fillRect(0, 0, width, height);

            if (variant === "landing") {
                const rightAmbient = ctx.createRadialGradient(
                    width * 0.92, height * 0.46, 0,
                    width * 0.92, height * 0.46, width * 0.54,
                );
                rightAmbient.addColorStop(0, "hsla(210, 18%, 100%, 0.08)");
                rightAmbient.addColorStop(0.22, "hsla(205, 18%, 92%, 0.035)");
                rightAmbient.addColorStop(0.55, "hsla(205, 18%, 82%, 0.015)");
                rightAmbient.addColorStop(1, "transparent");
                ctx.fillStyle = rightAmbient;
                ctx.fillRect(0, 0, width, height);
            }

            const leftShadow = ctx.createRadialGradient(
                width * 0.18, height * 0.5, 0,
                width * 0.18, height * 0.5, width * 0.62,
            );
            leftShadow.addColorStop(0, "hsla(228, 24%, 4%, 0)");
            leftShadow.addColorStop(0.6, "hsla(228, 24%, 4%, 0.32)");
            leftShadow.addColorStop(1, "hsla(228, 24%, 4%, 0.82)");
            ctx.fillStyle = leftShadow;
            ctx.fillRect(0, 0, width, height);
        };

        const drawStars = (elapsed: number, width: number, height: number) => {
            for (const star of stars) {
                star.x += star.driftX;
                star.y += star.driftY;

                if (star.x < -6) star.x = width + 6;
                if (star.x > width + 6) star.x = -6;
                if (star.y < -6) star.y = height + 6;
                if (star.y > height + 6) star.y = -6;

                const twinkle = 0.45 + (Math.sin(elapsed * star.twinkle + star.phase) + 1) * 0.25;
                const alpha = star.opacity * twinkle;

                ctx.beginPath();
                ctx.arc(star.x, star.y, star.size, 0, TAU);
                ctx.fillStyle = `hsla(210, 18%, 92%, ${alpha})`;
                ctx.fill();

                if (star.size > 1.2) {
                    ctx.beginPath();
                    ctx.arc(star.x, star.y, star.size * 2.8, 0, TAU);
                    ctx.fillStyle = `hsla(210, 18%, 92%, ${alpha * 0.08})`;
                    ctx.fill();
                }
            }
        };

        const drawMist = (elapsed: number) => {
            ctx.globalCompositeOperation = "screen";

            for (const cloud of clouds) {
                const driftAngle = cloud.orbitAngle + elapsed * cloud.drift * 0.08;
                const x = focusX * cloud.anchor + Math.cos(driftAngle) * cloud.orbitRadius;
                const y = focusY + cloud.yOffset + Math.sin(elapsed * cloud.drift + cloud.phase) * 26;
                const pulse = 0.85 + Math.sin(elapsed * 0.18 + cloud.phase) * 0.18;
                const opacity = cloud.opacity * pulse;
                const roll = cloud.rotation + Math.sin(elapsed * cloud.drift * 0.32 + cloud.phase) * 0.22;
                const radius = cloud.radius * (0.96 + Math.sin(elapsed * 0.24 + cloud.phase) * 0.04);

                ctx.save();
                ctx.translate(x, y);
                ctx.rotate(roll);
                ctx.scale(cloud.stretchX, cloud.stretchY);

                const coreGradient = ctx.createRadialGradient(0, 0, 0, 0, 0, radius);
                coreGradient.addColorStop(0, `hsla(${cloud.hue}, ${cloud.saturation}%, ${cloud.lightness + 2}%, ${opacity * 1.95 * cloud.density})`);
                coreGradient.addColorStop(0.18, `hsla(${cloud.hue}, ${cloud.saturation}%, ${cloud.lightness - 4}%, ${opacity * 1.28 * cloud.density})`);
                coreGradient.addColorStop(0.48, `hsla(${cloud.hue}, ${Math.max(cloud.saturation - 4, 4)}%, ${cloud.lightness - 18}%, ${opacity * 0.52})`);
                coreGradient.addColorStop(1, "transparent");
                ctx.fillStyle = coreGradient;
                ctx.fillRect(-radius, -radius, radius * 2, radius * 2);

                const lobeOffsetX = radius * 0.28;
                const lobeOffsetY = -radius * 0.12;
                const sideGradient = ctx.createRadialGradient(
                    -lobeOffsetX, lobeOffsetY, 0,
                    -lobeOffsetX, lobeOffsetY, radius * 0.94,
                );
                sideGradient.addColorStop(0, `hsla(${cloud.hue}, ${cloud.saturation}%, ${cloud.lightness + 6}%, ${opacity * 1.18})`);
                sideGradient.addColorStop(0.34, `hsla(${cloud.hue}, ${Math.max(cloud.saturation - 2, 4)}%, ${cloud.lightness - 4}%, ${opacity * 0.56})`);
                sideGradient.addColorStop(1, "transparent");
                ctx.fillStyle = sideGradient;
                ctx.fillRect(-radius, -radius, radius * 2, radius * 2);

                const rimGradient = ctx.createRadialGradient(
                    radius * 0.18, -radius * 0.08, 0,
                    radius * 0.18, -radius * 0.08, radius * 1.12,
                );
                rimGradient.addColorStop(0, "transparent");
                rimGradient.addColorStop(0.44, `hsla(${cloud.hue}, ${Math.max(cloud.saturation - 8, 4)}%, ${cloud.lightness - 10}%, ${opacity * 0.22 * cloud.glow})`);
                rimGradient.addColorStop(0.72, `hsla(${cloud.hue}, ${Math.max(cloud.saturation - 10, 4)}%, ${cloud.lightness - 26}%, ${opacity * 0.14 * cloud.glow})`);
                rimGradient.addColorStop(1, "transparent");
                ctx.fillStyle = rimGradient;
                ctx.fillRect(-radius * 1.15, -radius * 1.15, radius * 2.3, radius * 2.3);

                ctx.restore();
            }

            ctx.globalCompositeOperation = "source-over";
        };

        const drawText = (elapsed: number) => {
            const width = canvas.offsetWidth;
            const height = canvas.offsetHeight;
            const fontSize = Math.min(width * (variant === "landing" ? 0.16 : 0.2) * textScale, 240 * textScale);
            const textX = variant === "landing" ? width * 0.35 : width * 0.48;
            const textY = variant === "landing" ? height * 0.5 : height * 0.46;
            const opacity = Math.min(elapsed / 1.8, 1) * (variant === "landing" ? 0.12 : 0.16);

            if (opacity < 0.001) return;

            ctx.save();
            ctx.font = `700 ${fontSize}px Georgia, "Times New Roman", serif`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";

            ctx.filter = `blur(${fontSize * 0.14}px)`;
            ctx.fillStyle = `hsla(210, 14%, 96%, ${opacity * 0.38})`;
            ctx.fillText("VAULT", textX, textY);

            ctx.filter = `blur(${fontSize * 0.04}px)`;
            ctx.fillStyle = `hsla(210, 16%, 98%, ${opacity * 0.62})`;
            ctx.fillText("VAULT", textX, textY);

            ctx.filter = "none";
            ctx.strokeStyle = `hsla(210, 20%, 98%, ${opacity * 0.72})`;
            ctx.lineWidth = 1;
            ctx.strokeText("VAULT", textX, textY);
            ctx.restore();
        };

        const drawLandingGlow = (elapsed: number, width: number, height: number) => {
            const lightX = width * 0.92;
            const lightY = height * 0.46 + Math.sin(elapsed * 0.2) * 8;

            ctx.save();
            ctx.globalCompositeOperation = "screen";

            const ambient = ctx.createRadialGradient(lightX, lightY, 0, lightX, lightY, width * 0.42);
            ambient.addColorStop(0, "hsla(210, 18%, 100%, 0.2)");
            ambient.addColorStop(0.18, "hsla(210, 18%, 96%, 0.09)");
            ambient.addColorStop(0.4, "hsla(205, 18%, 82%, 0.04)");
            ambient.addColorStop(1, "transparent");
            ctx.fillStyle = ambient;
            ctx.fillRect(0, 0, width, height);

            const beam = ctx.createLinearGradient(width * 0.3, 0, width, 0);
            beam.addColorStop(0, "transparent");
            beam.addColorStop(0.42, "hsla(210, 18%, 96%, 0.012)");
            beam.addColorStop(0.72, "hsla(210, 18%, 96%, 0.06)");
            beam.addColorStop(0.9, "hsla(210, 18%, 100%, 0.13)");
            beam.addColorStop(1, "transparent");
            ctx.filter = "blur(28px)";
            ctx.fillStyle = beam;
            ctx.fillRect(width * 0.24, height * 0.16, width * 0.86, height * 0.62);

            const secondaryBeam = ctx.createLinearGradient(width * 0.46, height * 0.08, width, height * 0.52);
            secondaryBeam.addColorStop(0, "transparent");
            secondaryBeam.addColorStop(0.28, "hsla(210, 18%, 100%, 0.018)");
            secondaryBeam.addColorStop(0.58, "hsla(210, 18%, 98%, 0.085)");
            secondaryBeam.addColorStop(0.78, "hsla(205, 18%, 84%, 0.045)");
            secondaryBeam.addColorStop(1, "transparent");
            ctx.filter = "blur(44px)";
            ctx.fillStyle = secondaryBeam;
            ctx.fillRect(width * 0.34, height * 0.06, width * 0.7, height * 0.68);

            const haze = ctx.createRadialGradient(
                width * 0.78, height * 0.52, 0,
                width * 0.78, height * 0.52, width * 0.22,
            );
            haze.addColorStop(0, "hsla(210, 16%, 100%, 0.08)");
            haze.addColorStop(0.35, "hsla(205, 16%, 90%, 0.035)");
            haze.addColorStop(1, "transparent");
            ctx.fillStyle = haze;
            ctx.fillRect(width * 0.48, height * 0.18, width * 0.44, height * 0.6);

            const fogShelf = ctx.createLinearGradient(0, height * 0.34, 0, height * 0.72);
            fogShelf.addColorStop(0, "transparent");
            fogShelf.addColorStop(0.28, "hsla(208, 16%, 88%, 0.028)");
            fogShelf.addColorStop(0.52, "hsla(208, 12%, 70%, 0.06)");
            fogShelf.addColorStop(0.82, "hsla(208, 12%, 40%, 0.04)");
            fogShelf.addColorStop(1, "transparent");
            ctx.filter = "blur(54px)";
            ctx.fillStyle = fogShelf;
            ctx.fillRect(width * 0.32, height * 0.22, width * 0.62, height * 0.56);

            const columnGlow = ctx.createRadialGradient(
                width * 0.86, height * 0.5, 0,
                width * 0.86, height * 0.5, width * 0.16,
            );
            columnGlow.addColorStop(0, "hsla(210, 18%, 98%, 0.11)");
            columnGlow.addColorStop(0.46, "hsla(205, 16%, 88%, 0.032)");
            columnGlow.addColorStop(1, "transparent");
            ctx.filter = "blur(26px)";
            ctx.fillStyle = columnGlow;
            ctx.fillRect(width * 0.68, height * 0.24, width * 0.28, height * 0.48);

            ctx.restore();
        };

        const drawBlackhole = (elapsed: number) => {
            ctx.globalCompositeOperation = "screen";

            const ambientHalo = ctx.createRadialGradient(focusX, focusY, 0, focusX, focusY, holeRadius * 6.4);
            ambientHalo.addColorStop(0, "hsla(210, 18%, 98%, 0.1)");
            ambientHalo.addColorStop(0.2, "hsla(210, 18%, 95%, 0.05)");
            ambientHalo.addColorStop(0.45, "hsla(206, 24%, 28%, 0.04)");
            ambientHalo.addColorStop(1, "transparent");
            ctx.fillStyle = ambientHalo;
            ctx.fillRect(focusX - holeRadius * 6.4, focusY - holeRadius * 6.4, holeRadius * 12.8, holeRadius * 12.8);

            const ringRotation = -0.42;
            ctx.save();
            ctx.translate(focusX, focusY);
            ctx.rotate(ringRotation);

            const ringWidth = holeRadius * 0.6;
            const ringGradient = ctx.createLinearGradient(-ringRadius, 0, ringRadius, 0);
            ringGradient.addColorStop(0, "transparent");
            ringGradient.addColorStop(0.18, "hsla(214, 18%, 74%, 0.14)");
            ringGradient.addColorStop(0.42, "hsla(210, 16%, 100%, 0.8)");
            ringGradient.addColorStop(0.55, "hsla(210, 18%, 90%, 0.36)");
            ringGradient.addColorStop(0.72, "hsla(212, 20%, 66%, 0.12)");
            ringGradient.addColorStop(1, "transparent");

            ctx.filter = `blur(${holeRadius * 0.2}px)`;
            ctx.strokeStyle = ringGradient;
            ctx.lineWidth = ringWidth;
            ctx.beginPath();
            ctx.ellipse(0, 0, ringRadius, holeRadius * 0.42, 0, 0, TAU);
            ctx.stroke();

            const hotArcOpacity = 0.25 + Math.sin(elapsed * 0.55) * 0.05;
            ctx.filter = `blur(${holeRadius * 0.07}px)`;
            ctx.strokeStyle = `hsla(0, 0%, 100%, ${hotArcOpacity})`;
            ctx.lineWidth = holeRadius * 0.12;
            ctx.beginPath();
            ctx.ellipse(0, 0, ringRadius * 0.9, holeRadius * 0.3, 0, -0.2, Math.PI * 0.92);
            ctx.stroke();

            ctx.filter = "none";
            ctx.restore();

            const lensGlow = ctx.createRadialGradient(
                focusX, focusY, holeRadius * 0.1,
                focusX, focusY, holeRadius * 2.7,
            );
            lensGlow.addColorStop(0, "hsla(210, 16%, 100%, 0.1)");
            lensGlow.addColorStop(0.4, "hsla(210, 18%, 94%, 0.04)");
            lensGlow.addColorStop(1, "transparent");
            ctx.fillStyle = lensGlow;
            ctx.fillRect(focusX - holeRadius * 2.7, focusY - holeRadius * 2.7, holeRadius * 5.4, holeRadius * 5.4);

            ctx.globalCompositeOperation = "source-over";

            const shadowWell = ctx.createRadialGradient(focusX, focusY, 0, focusX, focusY, holeRadius * 2.15);
            shadowWell.addColorStop(0, "hsla(228, 30%, 2%, 1)");
            shadowWell.addColorStop(0.32, "hsla(228, 28%, 2%, 0.98)");
            shadowWell.addColorStop(0.68, "hsla(226, 22%, 4%, 0.78)");
            shadowWell.addColorStop(1, "transparent");
            ctx.fillStyle = shadowWell;
            ctx.fillRect(focusX - holeRadius * 2.15, focusY - holeRadius * 2.15, holeRadius * 4.3, holeRadius * 4.3);

            ctx.beginPath();
            ctx.arc(focusX, focusY, holeRadius * 0.98, 0, TAU);
            ctx.fillStyle = "hsl(228 30% 2%)";
            ctx.fill();

            ctx.beginPath();
            ctx.arc(focusX, focusY, holeRadius * 1.08, 0, TAU);
            ctx.strokeStyle = "hsla(210, 18%, 100%, 0.08)";
            ctx.lineWidth = 1;
            ctx.stroke();
        };

        const drawAccretionParticles = () => {
            if (!showParticles) return;

            ctx.globalCompositeOperation = "screen";

            for (const particle of particles) {
                particle.angle += particle.speed;
                particle.radius -= 0.22;

                if (particle.radius < holeRadius * 1.08) {
                    resetParticle(particle);
                }

                const x = focusX + Math.cos(particle.angle) * particle.radius;
                const y = focusY + Math.sin(particle.angle) * particle.radius * particle.axis;
                const trailX = focusX + Math.cos(particle.angle - particle.speed * 12) * (particle.radius + 3);
                const trailY = focusY + Math.sin(particle.angle - particle.speed * 12) * (particle.radius + 3) * particle.axis;
                const alpha = particle.opacity * Math.max(0.18, particle.radius / (ringRadius * 1.55));

                ctx.beginPath();
                ctx.moveTo(trailX, trailY);
                ctx.lineTo(x, y);
                ctx.strokeStyle = `hsla(${particle.hue}, 20%, 92%, ${alpha * 0.24})`;
                ctx.lineWidth = particle.size * 0.7;
                ctx.stroke();

                ctx.beginPath();
                ctx.arc(x, y, particle.size, 0, TAU);
                ctx.fillStyle = `hsla(${particle.hue}, 18%, 96%, ${alpha})`;
                ctx.fill();
            }

            ctx.globalCompositeOperation = "source-over";
        };

        const drawVignette = (width: number, height: number) => {
            const vignette = ctx.createRadialGradient(width * 0.5, height * 0.45, 0, width * 0.5, height * 0.45, width * 0.72);
            vignette.addColorStop(0, "transparent");
            vignette.addColorStop(0.58, "hsla(228, 26%, 3%, 0.08)");
            vignette.addColorStop(1, "hsla(228, 26%, 3%, 0.86)");
            ctx.fillStyle = vignette;
            ctx.fillRect(0, 0, width, height);
        };

        const render = (frameTime: number) => {
            const width = canvas.offsetWidth;
            const height = canvas.offsetHeight;
            const elapsed = frameTime / 1000;

            ctx.clearRect(0, 0, width, height);

            drawBase(width, height);
            drawStars(elapsed, width, height);
            drawMist(elapsed);
            if (showText && variant !== "landing") {
                drawText(elapsed);
            }
            if (variant === "landing") {
                drawLandingGlow(elapsed, width, height);
            } else {
                drawAccretionParticles();
                drawBlackhole(elapsed);
            }
            drawVignette(width, height);

            if (!prefersReducedMotion) {
                animationId = window.requestAnimationFrame(render);
            }
        };

        resize();
        if (prefersReducedMotion) {
            render(performance.now());
        } else {
            animationId = window.requestAnimationFrame(render);
        }
        window.addEventListener("resize", resize);

        return () => {
            window.cancelAnimationFrame(animationId);
            window.removeEventListener("resize", resize);
        };
    }, [showParticles, showText, textScale, variant]);

    return (
        <canvas
            ref={canvasRef}
            className="absolute inset-0 h-full w-full"
            style={{ background: "hsl(228 26% 3%)" }}
        />
    );
}
